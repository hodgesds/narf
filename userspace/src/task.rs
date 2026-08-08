//! Refcounted task lifetime — NARF's `task_struct`.
//!
//! Linux mapping: `Arc<Task>` ≙ `task_struct` + its refcount
//! (`get_task_struct`/`put_task_struct` ≙ `Arc::clone`/drop);
//! [`TASKS`] ≙ the pid table (holds one ref while the task is
//! findable); [`release_task`] ≙ `release_task()`.
//!
//! Lifetime rules (see `docs/TASK_LIFETIME_REDESIGN.md`):
//!
//! 1. `TASKS` holds exactly one `Arc` from spawn registration until
//!    the task is reaped ([`release_task`]). Any holder that needs the
//!    task beyond a lock section clones the `Arc` — dereferencing NEVER
//!    requires holding the registry lock. This replaces the old
//!    `USER_TASK_CTXS` raw-`*mut UserTaskCtx` registry whose safety
//!    hung on a deref-under-lock convention.
//! 2. The task's `UserTaskFuture` holds an `Arc<Task>` for its whole
//!    life, so the executor dropping the slot is a ref-put, not a free
//!    — and the `UserTaskCtx` address stays stable (and valid) for
//!    every raw self-pointer the in-flight trap/syscall paths hold.
//! 3. Exit marks the task [`TASK_ZOMBIE`] (it stays findable, carrying
//!    its exit code, until the parent reaps). Reaping removes the
//!    registry ref; the memory is freed when the LAST `Arc` drops.
//! 4. IRQ contexts must never drop an `Arc<Task>` (NARF forbids
//!    allocator frees in IRQ context — the `deferred_wake` rule). IRQ
//!    paths keep operating on tids + `Arc<WakeCell>` wakers only.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::user_task::UserTaskCtx;

/// Task is live (running or parked).
pub const TASK_RUNNING: u32 = 0;
/// Task has executed its exit path; only the reap-visible husk
/// (exit code, identity) is meaningful. Still present in [`TASKS`].
pub const TASK_ZOMBIE: u32 = 2;

/// The kernel-side task object. One per user task, shared by `Arc`.
pub struct Task {
    /// Scheduler `TaskId.raw()` — monotonic, NEVER reused. This
    /// monotonicity is the ABA-safety anchor for every tid-keyed
    /// table; do not introduce tid recycling.
    pub tid: u64,
    /// POSIX pid (thread-group id). PIDs ARE reused (lowest-free
    /// pool), so pid-keyed state must be cleaned at reap.
    pub pid: AtomicU64,
    /// [`TASK_RUNNING`] | [`TASK_ZOMBIE`].
    pub state: AtomicU32,
    /// Raw wstatus staged at exit (also mirrored in the pending-
    /// termination table until the reap plumbing migrates here).
    pub exit_code: AtomicI32,
    /// Set by `exit_group(2)` (Linux `signal->group_exit`): the whole
    /// thread group is terminating. Consulted so a sibling that races
    /// the group exit reports the group's status.
    pub group_exiting: core::sync::atomic::AtomicBool,
    /// Per-task user context: saved `UserState`, park/wait flags,
    /// futex/epoll generations. Owned HERE (not by the future) so its
    /// address is valid for as long as ANY `Arc<Task>` lives.
    pub uctx: UserTaskCtx,
    /// The file references an in-flight blocking `poll`/`ppoll` resolved at
    /// syscall ENTRY, one slot per `pollfd` (`None` = the fd was already
    /// closed then). Empty when no blocking poll is in flight.
    ///
    /// Linux's `do_sys_poll` resolves every fd to a `struct file` once, on
    /// entry, and holds those references for the whole call — so a `close()`
    /// from a SIBLING THREAD is invisible to a poll already in progress.
    /// NARF's park re-executes the syscall on each wake, which re-read the fd
    /// table every time; a sibling close then turned an in-flight poll into
    /// an instant `POLLNVAL` return, and event loops that treat that as a
    /// spurious wake re-poll immediately and spin.
    ///
    /// Holding the `Arc`s here reproduces Linux's lifetime rule: the file
    /// stays alive for the duration of the poll, exactly as a referenced
    /// `struct file` does. Per-TASK, deliberately — a global side table would
    /// put a shared lock on every blocking poll.
    ///
    /// The stored offset is only a FALLBACK for an fd that has since been
    /// closed. While the fd is still open the current offset is re-read from
    /// the fd table, because in Linux the offset (`f_pos`) lives in the same
    /// `struct file` being polled and stays live — that is what keeps an
    /// offset-gated reader like `/dev/kmsg` re-evaluating correctly.
    pub poll_files: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<PollFileSlot>>,
}

/// One entry of [`Task::poll_files`]: the resolved file and the offset it
/// had at poll entry. `None` when the fd named no open file.
pub type PollFileSlot = Option<(Arc<dyn narf_filesystem::FileOps>, u64)>;

impl Task {
    /// Create and register a task under `tid`. The caller must have
    /// reserved `tid` via `narf_scheduler::alloc_task_id()` and must
    /// register BEFORE the task is enqueued, so the task can resolve
    /// itself from its very first syscall.
    pub fn new_registered(tid: u64, pid: u64) -> Arc<Task> {
        let t = Arc::new(Task {
            tid,
            pid: AtomicU64::new(pid),
            state: AtomicU32::new(TASK_RUNNING),
            exit_code: AtomicI32::new(0),
            group_exiting: core::sync::atomic::AtomicBool::new(false),
            uctx: UserTaskCtx::new(),
            poll_files: narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new()),
        });
        TASKS.lock().insert(tid, t.clone());
        // /proc/[pid]/stat starttime source — every task (spawn, fork,
        // clone, the abi-test harness) registers exactly once, so this
        // is THE creation timestamp. Swept with the other per-task
        // tables at exit.
        crate::handlers::record_task_start_ns(tid);
        t
    }
}

impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Task")
            .field("tid", &self.tid)
            .field("pid", &self.pid.load(Ordering::Relaxed))
            .field("state", &self.state.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// The task registry — NARF's pid table. Holds ONE `Arc` per task
/// from spawn to reap.
static TASKS: IrqSafeSpinLock<BTreeMap<u64, Arc<Task>>> = IrqSafeSpinLock::new(BTreeMap::new());

/// `get_task_struct`: resolve a tid to a live (or zombie) task,
/// taking a reference. Safe to dereference after the registry lock is
/// released — that is the whole point.
pub fn task_get(tid: u64) -> Option<Arc<Task>> {
    TASKS.lock().get(&tid).cloned()
}

/// `unix-latency-trace`: print a one-line park report for every task
/// currently parked in a syscall.
///
/// The watchdog's own `PARK-CENSUS` cannot serve this purpose: it runs
/// behind `stall_wd`'s `DUMPED` gate, which latches on the first dump of
/// the boot (an early RCU stall trips it around t+25 s), so on a real
/// desktop run the census never fires. This one is called from ahead of
/// that gate and repeats, which is what a process that freezes MINUTES
/// into the session requires.
///
/// `scans` (`dbg_poll_scans`) is the progress signal that matters: a
/// healthy parked poller re-executes its syscall on a 1 ms deadline, so
/// `scans`/`checks` climb. Both frozen across successive reports, with
/// `parked=1`, is a park that never re-fires.
///
/// Called from the timer trap, so it inherits that context's hazards: it
/// allocates (the snapshot Vec) and holds `Arc<Task>` clones. Both are
/// things NARF's task-lifetime rules tell IRQ paths not to do. It is safe
/// only because `TASKS` holds a ref for every task listed, so no drop here
/// is ever the last one — and it is compiled out entirely without the
/// feature. Do not promote this to a non-debug path.
// ── `unix-latency-trace`: user-mode sampling profiler ────────────────
//
// "This process burns 41 s of user CPU before it starts serving" is where
// the park census runs out. It says the task is computing, not stalled,
// and nothing about WHAT. The timer trap already captures the interrupted
// RIP on every tick, so a histogram of that RIP — sampled only while the
// target task is in CPL 3 — is a profiler for free.
//
// Open-addressed, fixed-size, alloc-free: this runs in IRQ context on
// every tick, where NARF forbids allocator calls. A full table drops
// samples and says so rather than growing.

/// Number of distinct RIPs the profile can hold. Power of two — the
/// index is a mask, not a modulo.
#[cfg(feature = "unix-latency-trace")]
const PROF_SLOTS: usize = 512;
#[cfg(feature = "unix-latency-trace")]
static PROF_RIP: [AtomicU64; PROF_SLOTS] = [const { AtomicU64::new(0) }; PROF_SLOTS];
#[cfg(feature = "unix-latency-trace")]
static PROF_CNT: [AtomicU64; PROF_SLOTS] = [const { AtomicU64::new(0) }; PROF_SLOTS];
/// tid being profiled; 0 = profiling off. Set by [`dbg_proc_roster`].
#[cfg(feature = "unix-latency-trace")]
static PROF_TID: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "unix-latency-trace")]
static PROF_SAMPLES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "unix-latency-trace")]
static PROF_DROPPED: AtomicU64 = AtomicU64::new(0);

/// comm of the task to profile. Exact match, so `kwin_wayland` does not
/// also catch `kwin_wayland_wr`.
#[cfg(feature = "unix-latency-trace")]
const PROF_COMM: &str = "kwin_wayland";

/// Record one user-mode RIP sample. Called from the timer trap on every
/// tick that interrupted CPL 3; returns immediately (one relaxed load)
/// unless `tid` is the profile target, so the non-target cost is a
/// predictable branch.
#[cfg(feature = "unix-latency-trace")]
#[inline]
pub fn dbg_profile_sample(tid: u64, rip: u64) {
    if tid == 0 || PROF_TID.load(Ordering::Relaxed) != tid {
        return;
    }
    PROF_SAMPLES.fetch_add(1, Ordering::Relaxed);
    // Bucket to 16 bytes: consecutive instructions in one hot basic block
    // should land in one row rather than filling the table with
    // near-duplicates.
    let key = rip & !0xF;
    let mut idx = ((key >> 4) as usize) & (PROF_SLOTS - 1);
    for _ in 0..16 {
        let cur = PROF_RIP[idx].load(Ordering::Relaxed);
        if cur == key {
            PROF_CNT[idx].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if cur == 0
            && PROF_RIP[idx]
                .compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            PROF_CNT[idx].fetch_add(1, Ordering::Relaxed);
            return;
        }
        idx = (idx + 1) & (PROF_SLOTS - 1);
    }
    PROF_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Print the hottest sampled RIPs for the profiled task.
///
/// Addresses are raw and unsymbolized; resolve them offline against the
/// task's mappings (the KDE work uses `INTERP_BIAS 0x4000_0000_0000`).
/// Even unresolved the shape is informative: samples clustered in one
/// narrow range are a hot loop, samples spread wide are broad work.
#[cfg(feature = "unix-latency-trace")]
fn dbg_profile_report() {
    use core::fmt::Write as _;
    let total = PROF_SAMPLES.load(Ordering::Relaxed);
    if total == 0 {
        return;
    }
    let tid = PROF_TID.load(Ordering::Relaxed);
    let dropped = PROF_DROPPED.load(Ordering::Relaxed);
    // System-wide perf deltas since the last report. Two things this
    // gives that nothing else here does:
    //
    //  * `utick`/`ktick` — a CPL-sampled user/kernel split that does NOT
    //    depend on `TASK_KERN_NS`, which the own-stack executor leaves at
    //    zero (the fold in `dispatch` is skipped whenever the syscall
    //    parked, i.e. almost always). Sampling cannot be defeated that way.
    //  * `fault` — whether a task burning user time is actually executing
    //    or thrashing on demand-paged mappings. `do_lookup_x` walking a
    //    symbol table it has to fault in page by page looks exactly like
    //    `do_lookup_x` doing arithmetic, until you count faults.
    //
    // System-wide, not per-task: fine while the profiled task dominates
    // the machine, misleading otherwise. Read it as a rate, not a total.
    static LAST: IrqSafeSpinLock<Option<narf_lib::perf::Snapshot>> = IrqSafeSpinLock::new(None);
    let now = narf_lib::perf::snapshot();
    let d = {
        let mut g = LAST.lock();
        let prev = g.replace(now);
        prev.map(|p| {
            (
                now.syscalls.saturating_sub(p.syscalls),
                now.page_faults.saturating_sub(p.page_faults),
                now.ctx.saturating_sub(p.ctx),
                now.user_ticks.saturating_sub(p.user_ticks),
                now.kernel_ticks.saturating_sub(p.kernel_ticks),
            )
        })
    };
    let (sc, pf, cx, ut, kt) = d.unwrap_or((0, 0, 0, 0, 0));
    let _ = writeln!(
        narf_console::TrapWriter,
        "PROFREP tid={tid} comm={PROF_COMM} samples={total} dropped={dropped} d_sysc={sc} d_fault={pf} d_ctx={cx} d_utick={ut} d_ktick={kt}"
    );
    // Top 8 by count. A linear rescan per pick keeps this alloc-free;
    // 8 * 512 relaxed loads every 10 s is not worth a sort buffer.
    let mut ceiling = u64::MAX;
    for _ in 0..8 {
        let mut best = (0usize, 0u64);
        for i in 0..PROF_SLOTS {
            let c = PROF_CNT[i].load(Ordering::Relaxed);
            if c > best.1 && c < ceiling {
                best = (i, c);
            }
        }
        if best.1 == 0 {
            break;
        }
        let _ = writeln!(
            narf_console::TrapWriter,
            "PROFTOP rip={:#x} n={} pct={}",
            PROF_RIP[best.0].load(Ordering::Relaxed),
            best.1,
            best.1 * 100 / total
        );
        ceiling = best.1;
    }
}

/// `unix-latency-trace`: compact roster of EVERY registered task —
/// `tid comm pid pptid state`.
///
/// `pptid`, not `ppid`, and the name is doing real work: `PARENT_OF` is
/// keyed by the child's visible PID but stores the parent's **TID**
/// (`parent_of_set(child_visible_pid, current_task_id())`). Reading it as
/// a pid silently produces a plausible-looking wrong tree.
///
/// [`dbg_park_census`] only reports PARKED tasks, so a child that is
/// running (or spinning) is invisible to it. That is exactly the gap when
/// the question is "which child is this parent blocked in `wait4` for":
/// the parent shows `wantpid=N`, and without a roster there is nothing to
/// resolve N against. Pair the two.
///
/// Same timer-trap hazards as [`dbg_park_census`]; see its note.
#[cfg(feature = "unix-latency-trace")]
pub fn dbg_proc_roster() {
    use core::fmt::Write as _;
    let tasks: alloc::vec::Vec<Arc<Task>> = TASKS.lock().values().cloned().collect();
    for t in tasks {
        let pid = t.pid.load(Ordering::Relaxed);
        let cpu = crate::handlers::cpu_split_ns_try(t.tid);
        // Arm the profiler on the first task that matches. Done here
        // because this is where comms are already being resolved; the
        // trap-side sampler only does a relaxed compare against the tid.
        if PROF_TID.load(Ordering::Relaxed) == 0
            && crate::handlers::proc_comm_of_task_try(t.tid).as_deref() == Some(PROF_COMM)
        {
            PROF_TID.store(t.tid, Ordering::Relaxed);
        }
        let _ = writeln!(
            narf_console::TrapWriter,
            "PROCREP tid={} comm={} pid={} pptid={} st={} parked={} ums={} kms={}",
            t.tid,
            crate::handlers::proc_comm_of_task_try(t.tid).unwrap_or_default(),
            pid,
            crate::handlers::parent_of_get_try(pid).map_or(-1i64, |p| p as i64),
            t.state.load(Ordering::Relaxed),
            t.uctx.parked_in_syscall.load(Ordering::Relaxed) as u8,
            // User vs in-syscall ms. A process that burns tens of seconds
            // before it starts serving is either computing (user — nothing
            // the kernel can fix) or paying for syscalls/faults (kernel —
            // ours). The single summed figure /proc/<pid>/stat feeds the
            // probe cannot tell those apart.
            cpu.map_or(u64::MAX, |(u, _)| u / 1_000_000),
            cpu.map_or(u64::MAX, |(_, k)| k / 1_000_000),
        );
        // argv, on its own line. `comm` alone cannot distinguish
        // `plasma-keyboard` run as a long-lived input method from the same
        // binary run as a one-shot query — and that distinction is the whole
        // question when a parent is blocked in `wait4` for it. PROC_ARGV is
        // written at execve time against the exec'ing task, so cloned
        // threads have no entry and drop out here on their own.
        let Some(argv) = crate::handlers::proc_argv_of_task_try(t.tid) else {
            continue;
        };
        if argv.is_empty() {
            continue;
        }
        let _ = write!(narf_console::TrapWriter, "PROCARGV tid={} argv=", t.tid);
        // NUL-separated pack -> one space-free token per argument, so a
        // line mangled by cross-CPU interleaving is still parseable.
        for (i, arg) in argv.split(|&b| b == 0).take(12).enumerate() {
            if arg.is_empty() {
                continue;
            }
            let _ = write!(
                narf_console::TrapWriter,
                "{}",
                if i == 0 { "" } else { "|" }
            );
            for &b in arg.iter().take(64) {
                let _ = write!(
                    narf_console::TrapWriter,
                    "{}",
                    if b.is_ascii_graphic() { b as char } else { '.' }
                );
            }
        }
        let _ = writeln!(narf_console::TrapWriter);
    }
    dbg_profile_report();
}

#[cfg(feature = "unix-latency-trace")]
pub fn dbg_park_census(tag: &str) {
    use core::fmt::Write as _;
    let tasks: alloc::vec::Vec<Arc<Task>> = TASKS.lock().values().cloned().collect();
    for t in tasks {
        let uc = &t.uctx;
        if !uc.parked_in_syscall.load(Ordering::Relaxed) {
            continue;
        }
        let _ = writeln!(
            narf_console::TrapWriter,
            "PARKREP{tag} tid={} comm={} pid={} pptid={} st={} scans={} checks={} pnfds={} epfd_enc={} netio={} waitchild={} wantpid={} waitid={} waitopts={:#x} futex={:#x} flock={:#x} deadline={:#x}",
            t.tid,
            crate::handlers::proc_comm_of_task_try(t.tid).unwrap_or_default(),
            t.pid.load(Ordering::Relaxed),
            crate::handlers::parent_of_get_try(t.pid.load(Ordering::Relaxed))
                .map_or(-1i64, |p| p as i64),
            t.state.load(Ordering::Relaxed),
            uc.dbg_poll_scans.load(Ordering::Relaxed),
            uc.dbg_park_checks.load(Ordering::Relaxed),
            uc.poll_wait_nfds.load(Ordering::Relaxed),
            uc.epoll_wait_fd.load(Ordering::Relaxed),
            uc.net_io_wait.load(Ordering::Relaxed) as u8,
            uc.wait_child_pending.load(Ordering::Relaxed) as u8,
            // `wait4`'s target: >0 a specific pid, -1 any child, 0 own
            // process group. Meaningless unless `waitchild=1`, but printed
            // unconditionally so a stale value is visible rather than
            // silently masked.
            uc.wait_child_want_pid.load(Ordering::Relaxed),
            // WHICH wait syscall, and with what options — a glibc
            // `waitpid(pid, ., 0)` and a Qt/glib `waitid(P_PID, ., WEXITED)`
            // look identical once parked, and they implicate completely
            // different userspace machinery.
            uc.wait_child_is_waitid.load(Ordering::Relaxed) as u8,
            uc.wait_child_options.load(Ordering::Relaxed),
            uc.futex_uaddr.load(Ordering::Relaxed),
            uc.flock_key.load(Ordering::Relaxed),
            uc.sleep_deadline_ns.load(Ordering::Relaxed),
        );
        // The fd set itself, not just its size. "Parked in poll, scanning
        // hard, and STILL not accepting" has two completely different
        // causes, and only the set tells them apart: if the starved
        // listener's fd is absent, the acceptor never asked about it (its
        // own event loop); if present, the scan is being asked and
        // answering wrong (ours). Truncated at POLL_WAIT_RECORD_MAX — the
        // `+` marks a set too wide to see all of.
        let n = uc.poll_wait_nfds.load(Ordering::Relaxed) as usize;
        if n > 0 {
            let shown = n.min(crate::user_task::POLL_WAIT_RECORD_MAX);
            let _ = write!(narf_console::TrapWriter, "PARKFDS{tag} tid={} fds=", t.tid);
            for i in 0..shown {
                // Slot encoding (see poll::record_poll_wait):
                // `events << 32 | (fd + 1)`; 0 = unused slot.
                let slot = uc.poll_wait_fds[i].load(Ordering::Relaxed);
                let fd = (slot as u32).wrapping_sub(1) as i32;
                // The concrete FileOps type behind the fd, same source
                // /proc/<pid>/fd uses for its `anon_inode:[Type]` link. An fd
                // NUMBER says nothing; "this poller has been sitting on
                // fd 50 for two minutes" only becomes a lead once fd 50 is
                // named a socket, a timerfd, or an inotify.
                // NOT `type_name_of_val(&*e.ops)`: `ops` is a `dyn FileOps`,
                // and that returns the TRAIT object's name — every fd comes
                // back "FileOps". (`/proc/<pid>/fd`'s `anon_inode:[…]` link
                // has the same defect for the same reason.) `stat().file_type`
                // is the real discriminator: Socket vs Fifo vs Special is
                // exactly the distinction a starved poller turns on.
                let kind = if fd >= 0 {
                    crate::fd::try_with_table(t.tid, |tab| {
                        tab.get(fd as u32)
                            .map(|e| match e.ops.stat().mode.file_type {
                                narf_filesystem::FileType::Socket => "sock",
                                narf_filesystem::FileType::Fifo => "fifo",
                                narf_filesystem::FileType::Special => "chr",
                                narf_filesystem::FileType::Block => "blk",
                                narf_filesystem::FileType::File => "reg",
                                narf_filesystem::FileType::Dir => "dir",
                                narf_filesystem::FileType::Symlink => "lnk",
                            })
                    })
                    .flatten()
                    .unwrap_or("?")
                } else {
                    "-"
                };
                let _ = write!(
                    narf_console::TrapWriter,
                    "{}{}/{:#x}/{}",
                    if i == 0 { "" } else { "," },
                    fd,
                    (slot >> 32) as u32,
                    kind
                );
            }
            let _ = writeln!(
                narf_console::TrapWriter,
                "{}",
                if n > shown { "+" } else { "" }
            );
        }
    }
}

/// Diagnostic snapshot for the stall watchdog: one entry per registered
/// task — `(tid, pid, state, sleep_deadline_ns, futex_uaddr,
/// futex_namespace, futex_park_gen, futex_val, net_io_wait,
/// wait_child_pending, flock_key, parked_in_syscall)`. Clones the Arcs out
/// under the lock, reads the
/// atomics lock-free after.
#[allow(clippy::type_complexity)]
pub fn dbg_park_snapshot() -> alloc::vec::Vec<(
    u64,
    u64,
    u32,
    u64,
    u64,
    u64,
    u64,
    u32,
    bool,
    bool,
    usize,
    bool,
)> {
    let tasks: alloc::vec::Vec<Arc<Task>> = TASKS.lock().values().cloned().collect();
    tasks
        .iter()
        .map(|t| {
            (
                t.tid,
                t.pid.load(Ordering::Relaxed),
                t.state.load(Ordering::Relaxed),
                t.uctx.sleep_deadline_ns.load(Ordering::Relaxed),
                t.uctx.futex_uaddr.load(Ordering::Relaxed),
                t.uctx.futex_namespace.load(Ordering::Relaxed),
                t.uctx.futex_park_gen.load(Ordering::Relaxed),
                t.uctx.futex_val.load(Ordering::Relaxed),
                t.uctx.net_io_wait.load(Ordering::Relaxed),
                t.uctx.wait_child_pending.load(Ordering::Relaxed),
                t.uctx.flock_key.load(Ordering::Relaxed),
                t.uctx.parked_in_syscall.load(Ordering::Relaxed),
            )
        })
        .collect()
}

/// Parked tasks whose epoll set already reports a ready descriptor —
/// `(tid, pid, epfd)` for each.
///
/// A task in this list has been told, by the very readiness scan its own
/// `epoll_wait` would run, that it has work; it is nonetheless asleep. That
/// is a stranded wakeup, and it is the one thing that distinguishes a
/// genuinely idle system from a wedged one: both have zero runnable tasks
/// and a flat forward-progress counter.
///
/// Without this, a lost edge on (say) a compositor's Wayland socket looks
/// exactly like an idle desktop — every CPU halts, the stall watchdog's
/// `runnable > 0` guard never trips, and nothing is ever reported.
pub fn dbg_stranded_wakes() -> alloc::vec::Vec<(u64, u64, u32)> {
    let tasks: alloc::vec::Vec<Arc<Task>> = TASKS.lock().values().cloned().collect();
    let mut out = alloc::vec::Vec::new();
    for t in tasks {
        if !t.uctx.parked_in_syscall.load(Ordering::Relaxed) {
            continue;
        }
        // `epoll_wait_fd` is stored biased by one so zero means "not in an
        // epoll wait" (fd 0 is a legitimate epoll descriptor).
        let encoded = t.uctx.epoll_wait_fd.load(Ordering::Relaxed);
        if encoded == 0 {
            continue;
        }
        let epfd = (encoded - 1) as u32;
        if crate::epoll::epoll_fd_has_ready(t.tid, epfd) {
            out.push((t.tid, t.pid.load(Ordering::Relaxed), epfd));
        }
    }
    out
}

/// One reported stranded `poll`/`ppoll` waiter:
/// `(tid, pid, fd, revents, park_checks, deadline_ns, net_io_wait,
/// wait_child_pending, stopped, scans)`.
pub type StrandedPollWaiter = (u64, u64, i32, u32, u64, u64, bool, bool, bool, u64);

/// Parked tasks whose recorded `poll`/`ppoll` fd set already contains a
/// ready descriptor, and which have not re-scanned since the previous
/// sighting (see the latch discussion below).
///
/// The epoll-only [`dbg_stranded_wakes`] could not see the case that
/// actually matters: a glib main loop (KWin, and every Qt application
/// using the GLib event dispatcher) parks in `ppoll`, not `epoll_wait`,
/// so its `epoll_wait_fd` is never set and it never appears there.
///
/// A ready fd on a "parked" task is NOT by itself evidence of a strand,
/// and `park_checks` does not make it one. `parked_in_syscall` is set
/// before the park but cleared only at syscall EXIT, so a task cycling
/// park → wake → re-execute → scan → park reads as parked for the whole
/// duration of a healthy blocking poll — with `park_checks` climbing
/// ~100/s off the backstop the entire time. Sampling a ready fd anywhere
/// in that window reports a WORKING compositor as stranded, which is
/// exactly what this probe did before the latch below existed.
///
/// `scans` is the discriminator, applied as a two-sample latch (see
/// [`crate::user_task::UserTaskCtx::dbg_poll_strand_latch`]): a task is
/// reported only if it is seen twice with a ready fd and has NOT re-run
/// its own `poll_common` readiness scan in between. A healthy poller
/// re-scans within one ~10 ms backstop, so a full watchdog interval
/// without one means the syscall genuinely never re-executes.
///
/// `park_checks` is still printed, but as a SECONDARY split of a
/// confirmed strand: climbing means the park loop reconsiders the task
/// and the stay-parked decision is wrong; frozen means the task is never
/// reconsidered at all — a lost wake. Those need opposite fixes.
///
/// The trailing fields discriminate WHICH park a frozen task is actually
/// in — `dbg_park_checks` only counts `park_should_block` /
/// `UserTaskFuture::poll` passes, and two park sites bypass both the
/// counter and the ~10 ms wheel backstop entirely:
///   * `wait_child_pending` — the task parked through
///     `own_stack_wait_child` (wait-child + signal waker only; no wheel
///     slot, no io waiter, no counter bump). A ppoll that reaches
///     `own_stack_block` with this flag stale-true is misrouted there.
///   * `stopped` — the task parked through `park_should_block`'s
///     job-stop arm (signal waker only; no wheel slot by design).
///   * `deadline_ns`/`net_io_wait` — a healthy deadline-arm park shows
///     `deadline != 0` + `net_io_wait == true` (io waiter + wheel
///     backstop armed). `deadline == 0` while parked means a
///     `wake_one` consumed the park state but the executor never
///     re-polled the slot — an executor/queue-side lost wake.
///   * `scans` — how many readiness passes this task's OWN poll park has
///     run (`UserTaskCtx::dbg_poll_scans`). Sample it twice: advancing
///     while an fd stays ready means `poll_scan` and this scan disagree
///     about the same fd; frozen means the syscall never re-executes.
///     `park_checks` cannot answer this — it climbs in both cases.
pub fn dbg_stranded_poll_waiters() -> alloc::vec::Vec<StrandedPollWaiter> {
    let tasks: alloc::vec::Vec<Arc<Task>> = TASKS.lock().values().cloned().collect();
    let mut out = alloc::vec::Vec::new();
    for t in tasks {
        if !t.uctx.parked_in_syscall.load(Ordering::Relaxed) {
            continue;
        }
        let n = t.uctx.poll_wait_nfds.load(Ordering::Acquire) as usize;
        if n == 0 {
            continue;
        }
        let recorded = n.min(crate::user_task::POLL_WAIT_RECORD_MAX);
        let scans = t.uctx.dbg_poll_scans.load(Ordering::Relaxed);
        let mut candidate = false;
        let mut ready_fds: alloc::vec::Vec<(i32, u32)> = alloc::vec::Vec::new();
        for slot in t.uctx.poll_wait_fds.iter().take(recorded) {
            let packed = slot.load(Ordering::Relaxed);
            if packed == 0 {
                continue;
            }
            // Stored as `(events << 32) | (fd + 1)` so a zeroed slot is
            // unambiguously "empty" rather than "fd 0".
            let fd = ((packed & 0xFFFF_FFFF) as u32).wrapping_sub(1) as i32;
            let want = (packed >> 32) as u32;
            // Ask the SAME question `poll_scan` asks, term for term:
            //   * `poll_readiness_at` with the fd's CURRENT offset, ops
            //     cloned out of the lock before polling (nested-epoll
            //     re-entrancy, see `poll_scan`). The offset-less
            //     `poll_readiness()` is a different oracle: `/dev/kmsg`
            //     overrides only `poll_readiness_at` (readable iff
            //     `offset < live_len`), so the trait default (`IN|OUT`)
            //     made every fully drained kmsg reader parked in ppoll
            //     report here as permanently POLLIN-stranded while
            //     `poll_scan` correctly re-parked it.
            //   * mask = `events | ERR|HUP|NVAL` — poll returns those
            //     unrequested, so a HUP-only-ready fd is a strand too.
            //   * closed fd → POLLNVAL: `poll_scan` returns immediately
            //     on it, so a task still parked on one is stranded.
            let always = crate::poll::POLL_ERR | crate::poll::POLL_HUP | crate::poll::POLL_NVAL;
            let ready = crate::fd::with_table(t.tid, |tbl| {
                tbl.get(fd as u32).map(|e| (e.ops.clone(), e.offset))
            })
            .flatten()
            .map(|(ops, offset)| ops.poll_readiness_at(offset))
            .unwrap_or(crate::poll::POLL_NVAL);
            if ready & (want | always) != 0 {
                candidate = true;
                ready_fds.push((fd, ready & (want | always)));
            }
        }
        // Two-sample latch (see `dbg_poll_strand_latch`), applied ONCE per
        // task after the whole fd set has been scanned — never per fd. A
        // per-fd decision arms the latch on the first ready fd and then
        // reports the SECOND one in the same pass off that fresh arm,
        // which defeats the two-sample rule for any multi-fd poll set (and
        // a wedged compositor's set is always multi-fd).
        //
        // Report only a task seen with a ready fd AND an unchanged scan
        // count since the previous sighting; otherwise arm/re-arm and stay
        // quiet. Without this the report cannot tell a wedged poller from a
        // working one, because `parked_in_syscall` stays true across a
        // healthy poll's whole park → wake → re-execute → scan cycle.
        if candidate {
            let latch = t.uctx.dbg_poll_strand_latch.load(Ordering::Relaxed);
            if latch != scans.wrapping_add(1) {
                t.uctx
                    .dbg_poll_strand_latch
                    .store(scans.wrapping_add(1), Ordering::Relaxed);
                continue;
            }
            for (fd, revents) in ready_fds {
                out.push((
                    t.tid,
                    t.pid.load(Ordering::Relaxed),
                    fd,
                    // The revents `poll_scan` would have returned — the
                    // unrequested-but-always-reported bits included, so a
                    // HUP/NVAL strand prints its actual cause.
                    revents,
                    t.uctx.dbg_park_checks.load(Ordering::Relaxed),
                    t.uctx.sleep_deadline_ns.load(Ordering::Relaxed),
                    t.uctx.net_io_wait.load(Ordering::Relaxed),
                    t.uctx.wait_child_pending.load(Ordering::Relaxed),
                    crate::handlers::is_task_stopped(t.tid),
                    scans,
                ));
            }
        } else {
            // Nothing ready this pass — disarm, so a task that becomes a
            // candidate later gets a fresh two-sample window instead of
            // being reported on its first sighting off a stale latch.
            t.uctx.dbg_poll_strand_latch.store(0, Ordering::Relaxed);
        }
    }
    out
}

/// The task currently executing on this CPU, if the scheduler has one
/// published. `None` in kernel-test harness contexts.
pub fn current_task() -> Option<Arc<Task>> {
    let tid = crate::handlers::current_task_id();
    if tid == 0 {
        return None;
    }
    task_get(tid)
}

/// Flip a task to ZOMBIE at the top of its exit path. Idempotent;
/// returns `false` if the task was unknown (kernel-test contexts).
pub fn mark_zombie(tid: u64) -> bool {
    match task_get(tid) {
        Some(t) => {
            t.state.store(TASK_ZOMBIE, Ordering::Release);
            true
        }
        None => false,
    }
}

/// `release_task()`: drop the registry's reference at reap time. The
/// memory is freed when the last outstanding `Arc` drops (typically
/// the executor slot's future, if it hasn't been dropped already).
/// Returns the removed task so callers can log/inspect.
pub fn release_task(tid: u64) -> Option<Arc<Task>> {
    TASKS.lock().remove(&tid)
}

/// Number of registered (live + zombie) tasks. Diagnostics only.
pub fn task_count() -> usize {
    TASKS.lock().len()
}

/// Scheduler slot-reap hook (installed at boot via
/// `narf_scheduler::set_slot_reap_hook`). Fires when the executor
/// drops a task slot through an ABNORMAL path — budget-cap revocation
/// or `ChargeOutcome::Kill` — where the task never got to run its own
/// exit sequence. Without this the task would stay RUNNING in the
/// registry forever and its exit observers (fd teardown, SIGCHLD,
/// parent wake) would never fire: the pre-refcount version of this
/// bug left a dangling `*mut UserTaskCtx` behind for `wake_signal`/
/// `wake_one` to dereference.
///
/// Runs in executor (non-IRQ) context, so taking locks and dropping
/// Arcs here is sound.
pub fn slot_reap_handler(id: narf_scheduler::TaskId) {
    let tid = id.raw();
    let Some(t) = task_get(tid) else {
        // Kernel-only task (never registered) — nothing to tear down.
        return;
    };
    if t.state.swap(TASK_ZOMBIE, Ordering::AcqRel) == TASK_ZOMBIE {
        // Already ran its own exit path; the slot drop is the normal
        // post-exit cleanup.
        return;
    }
    let pid = t.pid.load(Ordering::Acquire);
    // The task died without a wstatus: report it as SIGKILL'd, then
    // fan out the same exit-observer sequence `terminate_current_task`
    // would have run (fd teardown, pending-exit staging, parent wake).
    crate::handlers::stage_killed_termination(pid);
    crate::user_task::notify_task_exited(pid, tid);
}

/// Test-only: clear the registry between kernel-test cases.
#[doc(hidden)]
pub fn __test_reset_tasks() {
    TASKS.lock().clear();
}
