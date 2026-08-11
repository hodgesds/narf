//! User-task polling-future glue.
//!
//! Stage-4 piece that lets a user-mode task live as a
//! `Future<Output = ()>` on the scheduler's run queue. The polling
//! contract:
//!
//! 1. The future owns a `UserTaskCtx` — a `UserState` slot for the
//!    saved CPU state plus a kernel-side `JmpBuf` for the
//!    polling-routine's setjmp.
//! 2. `poll(cx)` calls setjmp; when setjmp returns 0 the routine
//!    either does the first-time `enter_user_mode(entry, stack)`
//!    or, on a re-poll, calls `enter_user_mode_resume(&state)`.
//!    Both never return — control reaches user mode.
//! 3. When the user issues a "yield-to-scheduler" syscall (Yield
//!    or any future await-style op), the trap handler:
//!      - calls `TrapContext::save_user_state` against the
//!        current task's `UserState`,
//!      - longjmps back into the polling routine with a sentinel
//!        marking why control returned (yielded / exited / etc.).
//! 4. The trap handler finds the calling task's UserTaskCtx via
//!    [`current_user_task`] — a single static slot the polling
//!    routine populates on entry. Single-CPU cooperative for now;
//!    SMP gets a per-CPU slot when that lands.
//!
//! `UserTaskFuture` itself is left to the caller — the future
//! shape depends on what wakers need to fire (immediate cooperative
//! Yield vs timer wake vs ring-completion wake). This module
//! provides the building blocks; tests / the scheduler-spawn path
//! wire them together.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU32, AtomicU64, Ordering};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub use narf_scheduler::UserState;

/// Stub `UserState` for non-x86_64 / non-aarch64 arches so this
/// module compiles uniformly. The arch-specific definition lives
/// in `narf_arch::<arch>::user_mode::UserState` and is re-exported
/// via `narf_scheduler` for the supported arches above.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UserState {
    pub pc: u64,
    pub sp: u64,
    pub spsr: u64,
    pub x: [u64; 31],
}

/// Reason the trap handler longjmp'd back into the polling routine.
/// The routine maps this to a `Poll<...>` value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserExit {
    /// User issued `Syscall::Yield` (or another cooperative-yield
    /// op). The future returns `Pending` and re-wakes immediately.
    Yielded,
    /// User issued `Syscall::ExitTask`. The future returns
    /// `Ready(())`.
    Exited,
}

/// Per-task context the polling routine installs in
/// [`current_user_task`] before transitioning to user mode. The
/// trap handler picks up the pointer, populates `state` from the
/// trap frame, sets `exit` to the reason it's yielding back, and
/// uses `arch_jmp_buf` to longjmp.
///
/// `arch_jmp_buf` is `[u64; 8]` — sized to hold either the x86_64
/// `JmpBuf` (rbx/rbp/r12-r15/rsp/rip = 64 bytes) or an aarch64
/// equivalent without forcing this module to import either.
/// Callers cast as appropriate.
///
/// `sleep_deadline_ns` is the per-task absolute monotonic-ns
/// deadline used by `sys_sleep`'s polling-future path. `0` means
/// "not sleeping". Set by the syscall handler before it longjmps
/// back; consulted by `UserTaskFuture::poll` before any user-mode
/// re-entry — if `now < deadline`, the future returns `Pending`
/// and `wake_by_ref` without entering user mode, letting the
/// executor round-robin other tasks.
#[repr(C)]
pub struct UserTaskCtx {
    pub state: UnsafeCell<UserState>,
    pub arch_jmp_buf: UnsafeCell<[u64; 8]>,
    /// Cell used by the trap handler to signal *why* it longjmp'd.
    /// Polling routine reads this after setjmp returns non-zero.
    pub exit_reason: UnsafeCell<u32>,
    /// Absolute monotonic-ns deadline for `sys_sleep`. `0` means
    /// not sleeping. AtomicU64 (rather than UnsafeCell<u64>) so a
    /// future SMP rework — where the syscall handler and poller
    /// might briefly share visibility across cores — keeps the
    /// same shape.
    pub sleep_deadline_ns: AtomicU64,
    /// Set true by `sys_epoll_wait`/`sys_poll` while parked so the
    /// poll routine registers this task's waker in the net-readiness
    /// table (`crate::handlers::register_io_waiter`). When inbound TCP
    /// data lands, `crate::readiness` fires those wakers so the task
    /// re-polls readiness immediately instead of waiting out its wheel
    /// deadline (~100 ms for redis's serverCron). Cleared on wake.
    pub net_io_wait: AtomicBool,
    /// `narf_net::readiness::generation()` snapshot taken by
    /// `sys_epoll_wait`/`sys_poll` just before its final readiness
    /// check. After registering the I/O waker, the park path refreshes
    /// this snapshot if it advanced. The generation is global, so an
    /// advance cannot prove that this task's interest set is ready;
    /// treating it as such would turn unrelated AF_UNIX or network
    /// activity into a tight epoll/poll return loop. A real missed
    /// source wake is recovered by the bounded I/O backstop timer.
    pub epoll_park_gen: AtomicU64,
    /// epoll fd currently entering the park handshake, encoded as fd+1 (zero
    /// means this I/O wait is not epoll). After registering the task waker,
    /// the park path passively re-scans this instance before switching out.
    /// That closes the level-triggered scan→register race without treating
    /// unrelated changes to the global readiness generation as our event.
    pub epoll_wait_fd: AtomicU64,
    /// Futex word address this task is blocked on (`FUTEX_WAIT`), or 0 when
    /// not futex-waiting. Set by `sys_futex` before it yields; the poll
    /// routine registers `cx.waker()` in the per-uaddr futex wait queue so a
    /// `FUTEX_WAKE` on that word wakes this task PROMPTLY (a real blocking
    /// futex, not the old fixed ~1ms nanosleep park). Mirrors `net_io_wait`.
    pub futex_uaddr: AtomicU64,
    /// Address-space namespace for `FUTEX_PRIVATE` queue lookup. Zero denotes
    /// a process-shared futex; non-zero is the shared `Arc<AddressSpace>`
    /// identity, so CLONE_VM threads match while unrelated processes using
    /// the same virtual address cannot consume each other's wakes.
    pub futex_namespace: AtomicU64,
    /// Snapshot of the per-uaddr `FUTEX_WAKE` counter taken by `sys_futex`
    /// just before it parks. The poll routine re-reads the live counter after
    /// registering the waker; if it advanced, a wake landed in the
    /// check→register window (lost-wakeup race) and the task self-wakes to
    /// re-enter user mode instead of sleeping. Mirrors `epoll_park_gen`.
    pub futex_park_gen: AtomicU64,
    /// The futex word value this task's `FUTEX_WAIT` parked on. The park
    /// loop re-reads the word on every backstop re-check and proceeds when
    /// it no longer matches (`handlers::futex_park_should_stay`) — the
    /// Linux-parity guard against wakeless word rewrites (musl's condvar
    /// `unlock_requeue` barrier handoff, robust-owner death): userspace
    /// futex protocols are entitled to change the word without waking the
    /// old word, and waiters must re-check rather than re-park forever.
    /// Retargeted alongside `futex_uaddr` when a `FUTEX_REQUEUE` moves
    /// this waiter to a new word.
    pub futex_val: AtomicU32,
    /// Set non-null by `sys_execve` to hand a freshly-built
    /// `ExecRequest` to the polling routine. The routine takes
    /// ownership via `Box::from_raw` after the EXECVE longjmp
    /// returns and uses it to swap the future's `process.address_
    /// space` / `entry` / `stack_top` for the new image's values.
    /// Reset to null on consumption.
    pub pending_exec: AtomicPtr<ExecRequest>,

    /// Set by `sys_arch_prctl(ARCH_SET_FS, value)` — the user-side
    /// FS_BASE override that should survive across preemption.
    /// The polling future restores FS_BASE on every poll from
    /// `process.fs_base`; without this override, an arch_prctl
    /// call would only stick until the first timer-driven trap +
    /// re-poll, then revert to NARF's synthetic-TLS FS_BASE and
    /// musl's TCB pointer reads would land on stale memory and
    /// SIGSEGV. `u64::MAX` sentinel = unset (real fs_base could
    /// legitimately be 0).
    pub pending_fs_base: AtomicU64,

    // ── wait4 cooperative parking ───────────────────────────────────
    //
    // When `sys_wait4` needs to block (no child has exited yet and
    // WNOHANG is not set), it:
    //   1. Stores the target pid in `wait_child_want_pid`.
    //   2. Stores the user status pointer in `wait_child_status_ptr`.
    //   3. Sets `wait_child_pending = true`.
    //   4. Saves the user state (RAX will be updated by the poll
    //      routine once a reap succeeds) and longjmps via the yield
    //      hook.
    //
    // `UserTaskFuture::poll` sees `wait_child_pending = true` and
    // calls the registered `WAIT_CHILD_CHECK_FN` to try the reap.
    // If the reap succeeds it writes the child pid into the saved
    // UserState.rax, clears the flag, and falls through to re-enter
    // user mode. If the reap fails it stores `cx.waker()` (via
    // `register_wait_child_waker`) and returns `Poll::Pending`
    // without scheduling a wake-by-ref — the task truly parks until
    // `on_child_exit` fires the waker.
    //
    // Mirror of the `WaitAsciiByteFuture` pattern in narf-input.
    /// Set by `sys_wait4` before longjmping; cleared by the poll
    /// routine once a successful reap has been written into the
    /// saved UserState.
    pub wait_child_pending: AtomicBool,

    /// `want_pid` argument forwarded from `sys_wait4`: > 0 = wait
    /// for a specific child, ≤ 0 = any child.
    pub wait_child_want_pid: AtomicI64,

    /// on a successful reap. `0` = caller passed NULL (discard).
    /// For a `waitid(2)` wait this instead holds the `siginfo_t*`.
    pub wait_child_status_ptr: AtomicU64,
    /// True when this task parked (own-stack kernel_switch yield) at
    /// some point inside the CURRENT syscall. Under own-stack a parked
    /// syscall RETURNS through `kernel_syscall_entry`'s kernel-time
    /// bracket, which would otherwise fold the entire parked span —
    /// seconds of wall-clock — into stime. The bracket swaps this flag
    /// and skips the fold when set (matching the longjmp paths, which
    /// never reach the fold at all).
    pub parked_in_syscall: core::sync::atomic::AtomicBool,
    /// Non-zero while this task is parked in a blocked F_SETLKW: the
    /// lock-table key it waits on. `park_should_block` registers the
    /// task's waker on `fd::locks`' per-key waiter queue through this,
    /// exactly like `futex_uaddr` routes to the futex queue, so an
    /// unlock wakes the waiter immediately instead of after its 1 ms
    /// wheel backstop.
    pub flock_key: core::sync::atomic::AtomicUsize,

    /// Non-zero while this task is parked in a blocking `rt_sigtimedwait`:
    /// the userspace `sigset_t` it is waiting on (bit N-1 = signal N — the
    /// same layout as `SIGNAL_PENDING`). Routes the park to the signal
    /// waker registry exactly like `flock_key` routes to the flock waiter
    /// queue: `park_should_block` registers the task in `SIGNAL_WAKERS`
    /// (so `wake_signal` from any raise path fires it promptly) and breaks
    /// the park when `handlers::sigwait_should_wake` reports a signal in
    /// the set pending (mask ignored — sigwait consumes blocked signals,
    /// the normal calling convention) or any other deliverable signal
    /// (→ the re-executed syscall returns -EINTR). Cleared on every park
    /// exit path and by the re-executed handler's return paths.
    pub sigwait_set: AtomicU64,

    /// Set by the signal-delivery path when it delivers an out-of-set
    /// (handler-bound) signal to a task parked in `rt_sigtimedwait`
    /// (`sigwait_set != 0`). Because the park RIP-rewinds and re-executes,
    /// the interrupting signal is DELIVERED on the resume's return-to-user
    /// (handler runs, pending bit cleared) BEFORE the re-executed syscall
    /// re-checks `pending & !mask & !set` — which then reads 0 and would
    /// re-park forever (the stress-ng --sigrt hang: SIGALRM never breaks
    /// sigwaitinfo). This flag survives that window so the re-execution
    /// returns -EINTR regardless of whether the bit was already consumed.
    /// Cleared with the other sigwait routing on every rt_sigtimedwait
    /// exit.
    pub sigwait_interrupted: core::sync::atomic::AtomicBool,

    /// STICKY sigwait reservation: the most recent `rt_sigtimedwait` set,
    /// kept armed ACROSS the gap between consecutive sigtimedwaits (unlike
    /// `sigwait_set`, which doubles as park routing and is cleared on every
    /// exit path). While non-zero, signals in the set are reserved for the
    /// waiter — `default_signal_delivery_restricted` won't hand them to a
    /// handler even in the window where the task is processing the previous
    /// wait's result (stress-ng --sigrt's relay window). Without this, a
    /// child with a queued backlog loses its graceful-shutdown `sival=0`
    /// marker to the nop-handler sigreturn chain in that window — a race
    /// Linux only wins by speed (its window is ~µs; NARF's, under a 16-vCPU
    /// TCG storm, is ms). Cleared whenever the task blocks in any OTHER
    /// wait (`park_should_block`'s non-sigwait branches) — the signal that
    /// it left the sigwaitinfo loop — so a program that stops sigwaiting
    /// gets normal handler delivery back at its next blocking point.
    pub sigwait_reserve: AtomicU64,

    /// Distinguishes `waitid(2)` from `wait4(2)` for the blocking
    /// path: when set, the reap writes a `siginfo_t` to
    /// `wait_child_status_ptr` and the syscall returns 0 rather than
    /// writing a wstatus `int` and returning the reaped pid.
    pub wait_child_is_waitid: AtomicBool,

    /// `options` argument forwarded from `sys_wait4`/`sys_waitid` for
    /// the blocking path. Carries WUNTRACED/WCONTINUED so the poll
    /// loop's reap check can also collect job-control stop/continue
    /// notifications, not just exits.
    pub wait_child_options: AtomicU32,

    /// Set by `sys_read` when a blocking read on the console fd finds the
    /// input ring empty: instead of the 1ms re-poll used for pipes, the
    /// task parks on the serial/keyboard IRQ's `BYTE_RING_WAKER`. The poll
    /// routine registers `cx.waker()` there and returns `Pending` WITHOUT a
    /// wake-by-ref, so the task truly idles (and the executor can halt)
    /// until a keystroke arrives — no busy-poll. Cleared by the poll once
    /// bytes are available, and the read re-executes (RIP was rewound).
    pub console_read_pending: AtomicBool,

    /// Absolute monotonic-ns deadline of an *in-flight* `epoll_wait`/`poll`
    /// call, or `0` when no such call is parked. `u64::MAX` is never stored
    /// (infinite-timeout waits leave this `0`).
    ///
    /// Distinct from `sleep_deadline_ns`, which is the scheduler's wake
    /// signal and is CLEARED by `UserTaskFuture::poll` the moment the
    /// deadline expires. `epoll_wait`/`poll` RIP-rewind and RE-EXECUTE on
    /// every wake (to re-check fd readiness), so they cannot recover their
    /// original deadline from the cleared `sleep_deadline_ns` — they would
    /// recompute a fresh `now + timeout` each wake and re-arm forever (a
    /// pure-timeout `epoll_wait` that should return 0 never would). This
    /// field is owned by the syscall handler: set on the FIRST entry of a
    /// finite-timeout wait, reused verbatim across re-executions, and
    /// cleared on return. The scheduler never touches it, so a fresh call
    /// after an unrelated `sleep(2)` can't inherit a stale deadline.
    pub blocking_deadline_ns: AtomicU64,

    /// Fd (+1) of a FIFO `open()` that has installed its per-open
    /// [`crate::fifo` handle] and is now BLOCKED waiting for the peer
    /// direction to open (O_RDONLY without a writer, or O_WRONLY without a
    /// reader). `0` = no such open in flight.
    ///
    /// A FIFO open's peer-rendezvous is Linux-blocking, and the park (like
    /// `read`'s) RIP-rewinds and RE-EXECUTES the `open` syscall. Re-running
    /// the whole open would resolve the path and install a SECOND fd on every
    /// wake — and, worse, drop the first handle's open count (so the peer it
    /// is waiting for could never observe it). This slot makes the re-entry
    /// idempotent: the handle is installed ONCE on the first entry (its open
    /// count then persists across the park, which is exactly what the peer
    /// waits on), the fd is stashed here, and each re-execution merely
    /// re-checks the peer count against the already-installed fd rather than
    /// re-opening. Cleared (and the fd returned) once the peer appears.
    pub fifo_open_pending_fd: AtomicU64,

    // ── stall-watchdog diagnostics ──────────────────────────────────
    /// Monotonic count of park-condition re-checks: bumped on every
    /// `park_should_block` pass (own-stack park loop) and every
    /// deadline-branch pass of `UserTaskFuture::poll` (longjmp parks).
    ///
    /// NOT bumped by `own_stack_wait_child` — a task parked in a blocking
    /// wait4/waitid (or a ppoll misrouted there by a stale
    /// `wait_child_pending`) shows a FROZEN counter even while healthy,
    /// because that loop re-checks only on child-exit/signal wakes and
    /// arms no wheel backstop. The stranded-poll report's `waitchild`
    /// field is the discriminator.
    ///
    /// This is the signal that distinguishes the two ways a task can sit
    /// parked forever. A HEALTHY parked task re-checks its condition on the
    /// ~10 ms lost-wake backstop (infinite parks and io-parks both arm it),
    /// so this counter climbs ~100/s even while the task never runs a user
    /// instruction and accumulates no /proc CPU time. A counter that is
    /// FROZEN while `parked_in_syscall` stays true means the task is never
    /// re-polled at all — its backstop registration or executor wake was
    /// lost — which no CPU-time metric can distinguish from ordinary idle.
    /// Monotonic-ns at which this task's CURRENT on-CPU kernel span began,
    /// or 0 when it is not executing in a syscall.
    ///
    /// In-syscall CPU time (`ru_stime` / `tms_stime` / `/proc` stat field
    /// 15) used to be one bracket across the whole syscall, discarded
    /// entirely when the syscall parked — because the span would otherwise
    /// include arbitrary off-CPU sleep. Under the own-stack executor almost
    /// every syscall parks at least once, so the accumulator stayed EMPTY
    /// for every task on the system and stime read 0 forever.
    ///
    /// Splitting the bracket at each park fixes both halves: the span is
    /// folded and cleared before yielding, restarted on resume, so what
    /// accumulates is exactly the on-CPU time and never the sleep.
    pub kern_span_start_ns: AtomicU64,
    pub dbg_park_checks: AtomicU64,
    /// The fd set of an in-flight blocking `poll`/`ppoll` park, recorded at
    /// park time so the stall watchdog can re-run the readiness scan for a
    /// wedged poller (the poll twin of `epoll_wait_fd`): each slot is
    /// `((events as u64) << 32) | (fd as u32 as u64 + 1)`, zero = empty.
    /// Only the first [`POLL_WAIT_RECORD_MAX`] entries are recorded;
    /// `poll_wait_nfds` carries the true set size. Cleared on every
    /// `poll_common` return path.
    pub poll_wait_fds: [AtomicU64; POLL_WAIT_RECORD_MAX],
    /// True nfds of the recorded in-flight poll park (may exceed the
    /// recorded window above), or 0 when no blocking poll is parked.
    pub poll_wait_nfds: AtomicU32,
    /// Monotonic count of readiness scans this task's own blocking `poll`
    /// park has run (`poll_common`'s pre-park `poll_scan`).
    ///
    /// This is the progress signal `dbg_park_checks` cannot give for a
    /// poll waiter. Both a healthy poller and a wedged one show a CLIMBING
    /// `dbg_park_checks`, because an io-park re-executes its syscall on
    /// every ~10 ms backstop wake and each re-execution parks again — so
    /// "the counter moves" says only that the task is being reconsidered,
    /// not that it is re-asking the readiness question.
    ///
    /// Comparing this against the watchdog's own scan splits the two
    /// remaining hypotheses cleanly. If it ADVANCES while the watchdog
    /// still sees a ready fd, the task IS re-scanning and `poll_scan`
    /// disagrees with the watchdog about the same fd — a readiness-oracle
    /// bug. If it is FROZEN, the syscall is never re-executed at all — a
    /// wake/executor bug. They need opposite fixes.
    pub dbg_poll_scans: AtomicU64,
    /// Two-sample latch for the stranded-poller report: `dbg_poll_scans + 1`
    /// as of the previous watchdog sighting of this task with a ready fd,
    /// or 0 when unlatched.
    ///
    /// A single sample cannot tell a strand from a healthy poller.
    /// `parked_in_syscall` is set before the park but cleared only at
    /// syscall EXIT, so a task cycling park → wake → re-execute → scan →
    /// park reads as "parked" for its entire blocking poll — and its
    /// `dbg_park_checks` climbs the whole time. Sampling a ready fd in that
    /// window reports a working compositor as stranded.
    ///
    /// The latch closes it: a candidate must be seen twice with `scans`
    /// UNCHANGED. A healthy poller re-scans within one ~10 ms backstop, so
    /// a full watchdog interval with a ready fd and no scan means the
    /// syscall genuinely never re-executes.
    pub dbg_poll_strand_latch: AtomicU64,
}

/// Recorded-fd window for [`UserTaskCtx::poll_wait_fds`]. Qt/glib main
/// loops poll a handful of fds; 16 covers every set seen in a Plasma
/// session while keeping the ctx growth bounded.
pub const POLL_WAIT_RECORD_MAX: usize = 16;

/// Whether parked tasks should record their polled fd set for the stall
/// watchdog's strand detector. Off by default — see `record_poll_wait`.
static POLL_WAIT_RECORDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable the diagnostic recording above. Called by the stall watchdog.
pub fn enable_poll_wait_recording() {
    POLL_WAIT_RECORDING.store(true, Ordering::Release);
}

#[inline]
pub fn poll_wait_recording_enabled() -> bool {
    POLL_WAIT_RECORDING.load(Ordering::Relaxed)
}

// SAFETY: cells are accessed only from the polling routine and
// from the trap handler. Both run on the same CPU at any point in
// time (single-CPU cooperative); the trap handler runs to
// completion before the polling routine continues. SMP support
// will require a per-CPU slot rather than a global static.
unsafe impl Sync for UserTaskCtx {}

impl Default for UserTaskCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl UserTaskCtx {
    /// Construct a fresh context with all state zeroed.
    pub fn new() -> Self {
        Self {
            state: UnsafeCell::new(UserState::default()),
            arch_jmp_buf: UnsafeCell::new([0; 8]),
            exit_reason: UnsafeCell::new(0),
            sleep_deadline_ns: AtomicU64::new(0),
            net_io_wait: AtomicBool::new(false),
            epoll_park_gen: AtomicU64::new(0),
            epoll_wait_fd: AtomicU64::new(0),
            futex_uaddr: AtomicU64::new(0),
            futex_namespace: AtomicU64::new(0),
            futex_park_gen: AtomicU64::new(0),
            futex_val: AtomicU32::new(0),
            pending_exec: AtomicPtr::new(core::ptr::null_mut()),
            pending_fs_base: AtomicU64::new(u64::MAX),
            wait_child_pending: AtomicBool::new(false),
            wait_child_want_pid: AtomicI64::new(0),
            wait_child_status_ptr: AtomicU64::new(0),
            parked_in_syscall: core::sync::atomic::AtomicBool::new(false),
            flock_key: core::sync::atomic::AtomicUsize::new(0),
            sigwait_set: AtomicU64::new(0),
            sigwait_interrupted: core::sync::atomic::AtomicBool::new(false),
            sigwait_reserve: AtomicU64::new(0),
            wait_child_is_waitid: AtomicBool::new(false),
            wait_child_options: AtomicU32::new(0),
            console_read_pending: AtomicBool::new(false),
            blocking_deadline_ns: AtomicU64::new(0),
            fifo_open_pending_fd: AtomicU64::new(0),
            kern_span_start_ns: AtomicU64::new(0),
            dbg_park_checks: AtomicU64::new(0),
            poll_wait_fds: [const { AtomicU64::new(0) }; POLL_WAIT_RECORD_MAX],
            poll_wait_nfds: AtomicU32::new(0),
            dbg_poll_scans: AtomicU64::new(0),
            dbg_poll_strand_latch: AtomicU64::new(0),
        }
    }
}

impl core::fmt::Debug for UserTaskCtx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserTaskCtx").finish_non_exhaustive()
    }
}

// Sentinel values the trap handler stores into `exit_reason` and
// the polling routine reads. `0` is reserved for "not set" so a
// stale slot can't masquerade as a real exit.
pub const EXIT_REASON_YIELDED: u32 = 1;
pub const EXIT_REASON_EXITED: u32 = 2;
/// Set by `sys_execve` when the calling task is about to be
/// re-imaged with a freshly-loaded program. The polling routine
/// reads `pending_exec`, swaps `process.address_space` /
/// `process.entry` / `process.stack_top` to the new image's
/// values, transitions back to `TaskState::Initial`, and re-
/// enters user mode at the new entry point. The task's id, fd
/// table, brk top, signal handler table, and per-pid bookkeeping
/// are all preserved (POSIX execve(2)).
pub const EXIT_REASON_EXECVE: u32 = 3;

/// Body of an `execve` request handed from the syscall handler
/// to the polling routine. Heap-allocated and stored in
/// `UserTaskCtx::pending_exec` as a raw pointer; the polling
/// routine takes ownership via `Box::from_raw` after the longjmp
/// returns. Owns its own `Arc<AddressSpace>` so the new AS
/// stays alive across the brief window between syscall handler
/// completion and polling-routine swap.
#[derive(Debug)]
pub struct ExecRequest {
    pub new_as: alloc::sync::Arc<narf_memory::AddressSpace>,
    pub entry: u64,
    pub stack_top: u64,
    pub fs_base: Option<u64>,
}

/// Per-CPU in-flight-task slot. The polling routine on each CPU
/// populates its own cell before transitioning to user mode; the trap
/// handler — which always runs on the *same* CPU as the task that
/// trapped — consults its own cell to find the calling task's
/// `UserTaskCtx`. With user tasks able to run on multiple CPUs
/// concurrently, this MUST be per-CPU: a single global slot would let
/// one CPU's poller clobber another's in-flight pointer.
static CURRENT: [AtomicPtr<UserTaskCtx>; narf_lib::percpu::MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const NULL: AtomicPtr<UserTaskCtx> = AtomicPtr::new(core::ptr::null_mut());
    [NULL; narf_lib::percpu::MAX_CPUS]
};

/// This CPU's in-flight-task cell.
#[inline]
fn current_slot() -> &'static AtomicPtr<UserTaskCtx> {
    &CURRENT[narf_lib::percpu::current_cpu()]
}

pub fn install_current(ctx: *mut UserTaskCtx) {
    current_slot().store(ctx, Ordering::Release);
}

pub fn clear_current() {
    current_slot().store(core::ptr::null_mut(), Ordering::Release);
}

// ── Per-task-own-stack FPU seam ─────────────────────────────────────
//
// In the own-stack model the user FPU (x87/SSE) is saved/restored across a
// kernel_switch by the SCHEDULER (`try_preempt_user`/`yield_current_stackful`),
// but the FPU area lives here in userspace (`UserTaskFuture::fpu`). The poll
// publishes a pointer to the in-flight task's FPU area in this CPU's slot; the
// scheduler drives FXSAVE/FXRSTOR through the installed hooks below.
#[cfg(target_arch = "x86_64")]
static CURRENT_FPU: [AtomicPtr<FpuArea>; narf_lib::percpu::MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const NULL: AtomicPtr<FpuArea> = AtomicPtr::new(core::ptr::null_mut());
    [NULL; narf_lib::percpu::MAX_CPUS]
};

#[cfg(target_arch = "x86_64")]
#[inline]
fn fpu_slot() -> &'static AtomicPtr<FpuArea> {
    &CURRENT_FPU[narf_lib::percpu::current_cpu()]
}

/// Publish this CPU's in-flight user-task FPU area (or null to clear).
/// Wired into `UserTaskFuture::poll`'s own-stack entry next.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
#[inline]
fn publish_current_fpu(p: *mut FpuArea) {
    fpu_slot().store(p, Ordering::Release);
}

/// FXSAVE the running user task's FPU into its published area. Installed as the
/// scheduler's user-FPU save hook (own-stack model). No-op if unpublished.
#[cfg(target_arch = "x86_64")]
pub fn user_fpu_save_current() {
    let p = fpu_slot().load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: `p` is the in-flight task's FpuArea on this CPU (≥
        // FPU_AREA_SIZE, 64-aligned); CR4.OSFXSR/OSXSAVE set; the kernel is
        // soft-float so user XMM/x87/AVX is still live at the preempt/park point.
        unsafe {
            narf_arch::x86_64::xsave::fpu_save(p as *mut u8);
        }
    }
}

/// FXRSTOR the running user task's FPU from its published area. Installed as the
/// scheduler's user-FPU restore hook (own-stack model). No-op if unpublished.
#[cfg(target_arch = "x86_64")]
pub fn user_fpu_restore_current() {
    let p = fpu_slot().load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: as `user_fpu_save_current`.
        unsafe {
            narf_arch::x86_64::xsave::fpu_restore(p as *const u8);
        }
    }
}

pub fn current_user_task() -> Option<*mut UserTaskCtx> {
    // Own-stack model: a task RESUMES from a park via `kernel_switch`, NOT a
    // re-poll, so `UserTaskFuture::poll`'s `install_current` does NOT re-run —
    // the per-CPU `CURRENT` cell keeps pointing at whichever task was last
    // FRESHLY polled, even after the executor switched to a different task. A
    // syscall handler (e.g. `sys_futex`) reading `current_user_task()` while a
    // RESUMED task runs would then operate on the WRONG task's `UserTaskCtx` —
    // a redis worker's futex wrote its wait-state into netserve's ctx, wedging
    // netserve's accept() into an infinite futex wait (net-smoke echo hang).
    // The executor's `current_task_id()` (the slot it is polling) is ALWAYS
    // correct, so resolve the ctx by id through the refcounted task registry.
    // The returned raw pointer targets the `Arc<Task>`-owned `UserTaskCtx`,
    // which stays valid until the LAST `Arc` drops — the registry holds one
    // ref until reap, and the in-flight task's own future holds another, so
    // a self-lookup can never dangle. Fall back to the `CURRENT` cell when
    // the registry has no entry (the in-kernel test harness never registers).
    #[cfg(target_arch = "x86_64")]
    if narf_scheduler::stackful::user_own_stack_enabled() {
        let id = crate::handlers::current_task_id();
        if let Some(t) = crate::task::task_get(id) {
            return Some(&t.uctx as *const UserTaskCtx as *mut UserTaskCtx);
        }
    }
    // Longjmp model (and the fallback): the in-flight polling routine publishes
    // its ctx in this CPU's `CURRENT` cell right before entering user mode and
    // clears it on the way back out.
    let p = current_slot().load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

// ── Per-task-own-stack syscall park ─────────────────────────────────
//
// In the own-stack model a blocking syscall does NOT longjmp back to the
// poll's trap-back half (that half no longer runs — the poll diverges on first
// entry). Instead the handler sets its park state + rewinds RIP exactly as
// before, then calls `own_stack_park()`, which registers the task's executor
// slot-`Waker` (so the event source re-polls us) and `kernel_switch`es out via
// `yield_current_stackful`. On resume it RE-CHECKS the condition (a spurious or
// early wake re-parks) and only returns once the condition clears — then the
// caller returns and the sysret tail re-executes the syscall at the rewound RIP
// (the same "re-execute on wake" contract the longjmp path had). This is the
// relocation of the poll dispatch's waker-registration to the park site; it
// mirrors `UserTaskFuture::poll`'s sleep/futex/io/console/signal-stop arms but
// uses the slot-waker instead of `cx.waker()`. wait4 is NOT handled here (it
// returns a reaped result, not a re-execute) — that handler parks natively.

/// Absolute-ns time at which to fire the lost-wake fallback timer for a park
/// with the given absolute `deadline_ns`.
///
/// - Infinite parks (`u64::MAX`: pause / blocking poll·epoll·futex with no
///   timeout) fire a ~10 ms backstop so a lost external wake self-heals.
/// - FINITE **io-wait** parks (poll/epoll with a real timeout whose real wake
///   is the io waker) ALSO get the ~10 ms backstop — clamped to never overshoot
///   the real deadline. Without this a lost cross-core io-wake strands the task
///   until the full finite deadline; a QtDBus worker poll()ing the system bus
///   with the 25 s D-Bus method timeout otherwise sleeps out the whole 25 s, so
///   kwin's `GetSession`/`TakeControl` times out and never opens the GPU. The
///   working io-waker still short-circuits the common case; this only bounds the
///   worst case, matching what infinite parks already do.
/// - Other finite parks (plain `sleep`/`nanosleep`) fire at their real deadline.
pub(crate) fn park_fire_deadline_ns(deadline_ns: u64, now_ns: u64, net_io_wait: bool) -> u64 {
    const FALLBACK_NS: u64 = 10_000_000; // ~1 tick @ 100 Hz
    if deadline_ns == u64::MAX {
        now_ns.saturating_add(FALLBACK_NS)
    } else if net_io_wait {
        now_ns.saturating_add(FALLBACK_NS).min(deadline_ns)
    } else {
        deadline_ns
    }
}

/// Record the readiness generation observed after an I/O waiter has been
/// registered, without cancelling its park.
///
/// `narf_net::readiness::generation()` is intentionally global: it closes the
/// crate-layering gap for sources that cannot name a particular waiter. That
/// also means a changed generation is not a predicate on this task's poll or
/// epoll interest set. Linux's `ep_poll()` queues the task and does its final
/// ready-list check under the epoll wait-queue lock; it does not return a
/// successful empty wait because another file became ready. NARF keeps the
/// waiter registered and refreshes the advisory snapshot instead. The existing
/// 10 ms I/O backstop guarantees a true scan→register lost wake is retried.
pub(crate) fn refresh_io_wait_generation_after_registration(uc: &UserTaskCtx, observed: u64) {
    uc.epoll_park_gen.store(observed, Ordering::Release);
}

/// Register `waker` with the park condition's event source and report whether
/// the task should actually block (`true`) or proceed/re-execute now (`false`,
/// condition already satisfied or a wake raced us). Mirrors the poll dispatch.
#[cfg(target_arch = "x86_64")]
fn park_should_block(
    uc: &UserTaskCtx,
    waker: &core::task::Waker,
    sleep_handle: &mut Option<narf_scheduler::narf_time::timer_wheel::SleepHandle>,
) -> bool {
    let task_id = crate::handlers::current_task_id();
    // Watchdog liveness signal: this task's park loop ran (see
    // `UserTaskCtx::dbg_park_checks`).
    uc.dbg_park_checks.fetch_add(1, Ordering::Relaxed);

    // Job-control stop (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU): stay parked until
    // SIGCONT clears the stopped flag (SIGKILL=bit 9 still breaks through).
    if crate::handlers::is_task_stopped(task_id)
        && (crate::handlers::signal_pending_bits(task_id) & (1 << 9)) == 0
    {
        crate::handlers::register_signal_waker(task_id, waker.clone());
        return true;
    }

    // Deadline-based park (sleep / nanosleep / pause / blocking poll·epoll·futex).
    let deadline = uc.sleep_deadline_ns.load(Ordering::Acquire);
    if deadline != 0 {
        let now = narf_scheduler::narf_time::monotonic_ns();
        // Linux interruptible-sleep semantics: a deliverable pending signal
        // breaks ANY deadline park — finite ones included. nanosleep/futex/
        // poll are all signal-interruptible on Linux (-EINTR); restricting
        // this to infinite (u64::MAX) parks left a finite-deadline sleeper
        // deaf to signals until its deadline — with a long deadline that is
        // a de-facto permanent strand (stress-ng --futex: the SIGKILL'd/
        // SIGALRM'd fork child parked in a timed FUTEX_WAIT never woke, the
        // parent spun in kill→wait4 forever). Ignored-signal safety: the
        // return-to-user delivery path CONSUMES pending SIG_IGN/default-
        // Ignore bits (see `deliver_one_signal`), so breaking the park can't
        // busy-spin on a bit nobody clears.
        let signal_pending = crate::handlers::is_signal_pending(task_id);
        if now < deadline && !signal_pending {
            // rt_sigtimedwait park: register in SIGNAL_WAKERS FIRST (every
            // raise path calls `wake_signal`, which fires this entry), THEN
            // re-check the wake condition — a signal raised in the
            // check→register window is caught by the re-check, a later one
            // by the waker; no lost-wake window either way. The `set`
            // intersection deliberately ignores the block mask (sigwait
            // consumes blocked signals); a deliverable signal OUTSIDE the
            // set also breaks the park so the re-executed syscall can
            // return -EINTR (Linux rt_sigtimedwait(2)).
            let sw = uc.sigwait_set.load(Ordering::Acquire);
            if sw != 0 {
                crate::handlers::register_signal_waker(task_id, waker.clone());
                if crate::handlers::sigwait_should_wake(task_id, sw) {
                    crate::handlers::drop_signal_waker(task_id);
                    uc.sleep_deadline_ns.store(0, Ordering::Release);
                    uc.sigwait_set.store(0, Ordering::Release);
                    return false; // signal arrived → re-execute the syscall
                }
            } else {
                // Non-sigwait park: the task left its sigwaitinfo loop —
                // release the sticky waiter reservation so signals it was
                // waiting on resume normal handler delivery.
                uc.sigwait_reserve.store(0, Ordering::Release);
                // Signal-interruptible park: register in SIGNAL_WAKERS FIRST
                // (every raise path — kill, itimer expiry, child exit — fires
                // this entry via `wake_signal`), THEN re-check the pending
                // set. A signal raised in the gate-check→register window is
                // caught by the re-check; a later one fires the waker. This
                // is the wake channel that lets a cross-CPU `kill()` unpark a
                // finite-deadline sleeper immediately instead of relying on
                // the timer wheel alone (whose wake can be arbitrarily far
                // out — the stress-ng --futex SMP strand).
                crate::handlers::register_signal_waker(task_id, waker.clone());
                if crate::handlers::is_signal_pending(task_id) {
                    crate::handlers::drop_signal_waker(task_id);
                    uc.sleep_deadline_ns.store(0, Ordering::Release);
                    uc.flock_key.store(0, Ordering::Release);
                    return false; // deliver on the re-executed syscall's return
                }
            }
            // Net I/O wait (epoll/poll flagged inbound TCP): register + lost-wake guard.
            if uc.net_io_wait.load(Ordering::Acquire) {
                crate::handlers::register_io_waiter(task_id, waker.clone());
                refresh_io_wait_generation_after_registration(
                    uc,
                    narf_net::readiness::generation(),
                );
                let encoded_epfd = uc.epoll_wait_fd.load(Ordering::Acquire);
                if encoded_epfd != 0
                    && crate::epoll::epoll_fd_has_ready(task_id, (encoded_epfd - 1) as u32)
                {
                    // Ready after the first userspace-facing scan but before
                    // waiter registration. The waiter is now installed, so a
                    // later transition is covered; do one immediate
                    // re-execution for the already-level-ready event instead
                    // of relying on the timer-wheel backstop.
                    crate::handlers::drop_io_waiter(task_id);
                    uc.sleep_deadline_ns.store(0, Ordering::Release);
                    return false;
                }
            }
            // FUTEX_WAIT: register on the per-uaddr queue + lost-wake guard.
            //
            // The stay-parked decision checks BOTH the per-uaddr wake
            // generation (a FUTEX_WAKE raced the check→register window)
            // AND the futex word itself (`futex_park_should_stay`). The
            // word re-validation is what keeps a wakeless word rewrite —
            // musl's condvar `unlock_requeue` barrier handoff, a robust
            // owner death — from re-parking this task forever on a word
            // nobody will ever wake again: Linux waiters get the same
            // safety from re-checking the word in userspace after any
            // (possibly spurious) futex_wait return, and this park loop
            // otherwise swallows the backstop wake inside the kernel.
            // NOTE: `fu` may have been retargeted by a FUTEX_REQUEUE while
            // this task was parked — the load below naturally re-registers
            // on the new word with the retargeted gen/val snapshots.
            let fu = uc.futex_uaddr.load(Ordering::Acquire);
            if fu != 0 {
                let key =
                    crate::handlers::futex_key(uc.futex_namespace.load(Ordering::Acquire), fu);
                crate::handlers::futex_register_waiter_key(key, task_id, waker.clone());
                let stay = crate::handlers::futex_park_should_stay(
                    crate::handlers::futex_gen_key(key),
                    uc.futex_park_gen.load(Ordering::Acquire),
                    crate::handlers::futex_read_user_word(fu),
                    uc.futex_val.load(Ordering::Acquire),
                );
                if !stay {
                    crate::handlers::futex_drop_waiter_key(key, task_id);
                    uc.sleep_deadline_ns.store(0, Ordering::Release);
                    uc.futex_uaddr.store(0, Ordering::Release);
                    uc.futex_namespace.store(0, Ordering::Release);
                    return false; // wake landed / word changed → re-execute (musl re-checks)
                }
            }
            // Blocked F_SETLKW: register on the lock key's waiter queue so
            // the holder's unlock (or exit) wakes this task immediately. No
            // re-check-after-register here — the request's full range isn't
            // carried in the ctx; an unlock that raced the registration is
            // caught by the 1 ms wheel backstop below, so the race costs one
            // backstop period, never a wedge.
            #[cfg(feature = "linux-compat")]
            {
                let fk = uc.flock_key.load(Ordering::Acquire);
                if fk != 0 {
                    crate::fd::locks::register_waiter(fk, task_id, waker.clone());
                }
            }
            // Park on the timer wheel. Infinite parks (u64::MAX) use a ~1-tick
            // fallback so a lost external wake can't wedge; finite sleeps use
            // the real deadline. The real wake is the io/futex/signal waker.
            //
            // The wheel deadline is ABSOLUTE TSC cycles compared against
            // `now_cycles()` in `fire_due`. `deadline`/`now` are absolute
            // monotonic NANOSECONDS (from `monotonic_ns()` = `cycles_to_ns`).
            // Convert with `ns_to_cycles` — the PRECISE mult-shift inverse of
            // that `cycles_to_ns` — NOT `* cycles_per_ns()`: the latter is a
            // truncated-integer rate that rounds the wrong way, putting the
            // deadline far in the future so a pure-deadline park (a blocking
            // `accept()` with no io/futex waker) NEVER fires and the task
            // strands. This only bit the own-stack park path; the longjmp
            // `UserTaskFuture::poll` already used `ns_to_cycles`.
            let fire_ns =
                park_fire_deadline_ns(deadline, now, uc.net_io_wait.load(Ordering::Acquire));
            let fire_cycles = narf_scheduler::narf_time::ns_to_cycles(fire_ns);
            // `refresh_waker_at`, NOT `refresh_waker`: the handle can outlive
            // an earlier park with a DIFFERENT deadline (a futex park broken
            // by its gen guard re-parks through here with a fresh deadline);
            // refreshing only the waker would leave the slot pinned to the
            // stale fire time and this park's backstop never fires.
            let refreshed = sleep_handle.is_some_and(|h| {
                narf_scheduler::narf_time::timer_wheel::refresh_waker_at(
                    h,
                    fire_cycles,
                    waker.clone(),
                )
            });
            if !refreshed {
                match narf_scheduler::narf_time::timer_wheel::register(fire_cycles, waker.clone()) {
                    Ok(h) => *sleep_handle = Some(h),
                    Err(_) => {
                        // Timer wheel saturated (single global 1024-slot wheel): we
                        // could NOT arm the lost-wake fallback timer. Blocking now
                        // would rely SOLELY on the io/futex/signal waker; if that
                        // wake then raced the idle-halt Dekker fence, the task
                        // could strand with no fallback re-poll. This asymmetry
                        // (own-stack park blocked anyway; `UserTaskFuture::poll`
                        // ALREADY self-wakes on this exact failure) is a residual
                        // permanent-wedge window that survives the futex seqlock
                        // fix — the wheel saturates far more readily under SMP
                        // (per-CPU idle-arming + concurrent parks contend one
                        // global wheel). Mirror the poll path: DON'T block —
                        // return false so own_stack_park re-executes and busy-
                        // rechecks the condition, retrying the wheel next round
                        // (it frees as other sleepers fire). Bounded busy-poll
                        // under transient pressure, never a permanent wedge.
                        uc.sleep_deadline_ns.store(0, Ordering::Release);
                        // Clear the flock/sigwait routing too — this exit
                        // skips the proceed-branch cleanup below, and a stale
                        // key would make the task's NEXT unrelated park
                        // register on the wrong waiter queue.
                        uc.flock_key.store(0, Ordering::Release);
                        uc.sigwait_set.store(0, Ordering::Release);
                        return false;
                    }
                }
            }
            return true;
        }
        // Deadline reached / signal pending → clear and proceed (re-execute).
        // Drop any signal-waker entry this park registered (no-op if
        // `wake_signal` already consumed it when it fired us).
        crate::handlers::drop_signal_waker(task_id);
        uc.sleep_deadline_ns.store(0, Ordering::Release);
        uc.net_io_wait.store(false, Ordering::Release);
        uc.futex_uaddr.store(0, Ordering::Release);
        uc.futex_namespace.store(0, Ordering::Release);
        // The waiter-queue entry (if any) is dropped by the re-executed
        // fcntl's exit paths, which know the key; just clear the routing.
        uc.flock_key.store(0, Ordering::Release);
        // Sigwait routing: the re-executed rt_sigtimedwait re-arms it if it
        // parks again (timeout expiry is detected via blocking_deadline_ns).
        uc.sigwait_set.store(0, Ordering::Release);
        if let Some(h) = sleep_handle.take() {
            narf_scheduler::narf_time::timer_wheel::cancel(h);
        }
        return false;
    }

    // Console blocking-read: register on the serial/keyboard IRQ byte-waker.
    if uc.console_read_pending.load(Ordering::Acquire) {
        // Non-sigwait park — release the sticky waiter reservation (see above).
        uc.sigwait_reserve.store(0, Ordering::Release);
        narf_input::register_byte_waker(waker);
        if narf_input::pending_input() > 0 {
            uc.console_read_pending.store(false, Ordering::Release);
            return false; // a byte is ready → re-execute the read
        }
        // ALSO arm a ~1-tick wheel fallback (like the deadline parks above):
        // the serial/keyboard byte-waker is a single non-Arc registry slot, so
        // a dropped/overwritten byte-ring wake would otherwise wedge the reader
        // (e.g. getty/login at boot) forever. The fallback re-runs this check on
        // the next tick — a robust backstop for any lost type-specific wake.
        // Convert via `ns_to_cycles` (precise inverse of `cycles_to_ns`), NOT
        // `* cycles_per_ns()` — see the deadline-park note above.
        let now = narf_scheduler::narf_time::monotonic_ns();
        const FALLBACK_NS: u64 = 10_000_000; // ~1 tick @ 100 Hz
        let fire = narf_scheduler::narf_time::ns_to_cycles(now.saturating_add(FALLBACK_NS));
        // `refresh_waker_at` — keep the slot's deadline current across
        // repeated parks through one handle (see the deadline-park note).
        let refreshed = sleep_handle.is_some_and(|h| {
            narf_scheduler::narf_time::timer_wheel::refresh_waker_at(h, fire, waker.clone())
        });
        if !refreshed {
            *sleep_handle =
                narf_scheduler::narf_time::timer_wheel::register(fire, waker.clone()).ok();
        }
        return true;
    }

    // No park state set (shouldn't happen on a park site) → proceed.
    false
}

/// Own-stack blocking-syscall park: register the slot-waker + `kernel_switch`
/// out, looping until the park condition clears. Returns to the caller (a
/// syscall handler that rewound RIP) so the sysret tail re-executes the syscall.
#[cfg(target_arch = "x86_64")]
pub fn own_stack_park() {
    let mut sleep_handle: Option<narf_scheduler::narf_time::timer_wheel::SleepHandle> = None;
    loop {
        let waker = match narf_scheduler::stackful::current_stackful_waker() {
            Some(w) => w,
            None => break, // no executor (kernel-test) — degrade to one proceed
        };
        let uctx = match current_user_task() {
            Some(u) => u,
            None => break,
        };
        // SAFETY: the in-flight task's poller-pinned UserTaskCtx; single-CPU
        // cooperative execution means no concurrent &mut to these fields.
        let uc = unsafe { &*uctx };
        if !park_should_block(uc, &waker, &mut sleep_handle) {
            if let Some(h) = sleep_handle.take() {
                narf_scheduler::narf_time::timer_wheel::cancel(h);
            }
            break;
        }
        // Close the on-CPU kernel span BEFORE yielding: everything from here
        // to the resume below is sleep, and billing it as stime is exactly
        // the mistake that made the whole-syscall bracket unusable.
        crate::handlers::close_kernel_span(uc, narf_scheduler::current_task_id().raw());
        // SAFETY: CPL0 on our own kernel stack, a stackful task is current.
        unsafe {
            (*uctx).parked_in_syscall.store(true, Ordering::Release);
            narf_scheduler::stackful::yield_current_stackful();
        }
        // ── Resumed via kernel_switch (NOT a re-poll) ── re-publish this task's
        // `CURRENT` cell: `install_current` runs only in `UserTaskFuture::poll`,
        // which does not re-run on an own-stack resume, so the executor's
        // intervening fresh-polls of OTHER tasks left `CURRENT` pointing at the
        // wrong ctx. A syscall handler reading `current_user_task()` for this
        // resumed task would otherwise touch a DIFFERENT task's `UserTaskCtx`
        // (observed: a redis worker's futex wrote its wait-state into netserve's
        // ctx → netserve's accept() wedged into an infinite futex wait → net
        // echo hang).
        install_current(uctx);
        // Resumed and executing again — re-open the span.
        // SAFETY: as above; `uctx` is this task's poller-pinned ctx.
        crate::handlers::open_kernel_span(unsafe { &*uctx });
        // An io-wait park (a readiness scan parked in poll/epoll/blocking
        // read) must RE-EXECUTE its syscall after ANY wake — including the
        // ~10 ms lost-wake backstop — so the readiness SCAN re-runs. Silent
        // sources (a pipe write, a timerfd expiry behind a nested epoll)
        // fire no readiness notify: re-checking only the park CONDITION
        // here finds the deadline unexpired + the generation unchanged and
        // re-parks forever, sleeping out an infinite-timeout poll no matter
        // how ready its fds are. Breaking out re-executes the rewound
        // syscall, whose pre-park sequence re-arms the park state — so a
        // spurious wake costs one bounded re-scan, matching the wake_one()
        // (clear-deadline → re-execute) contract. Non-io parks
        // (sleep/futex/console/job-stop) keep the re-check loop.
        if uc.net_io_wait.load(Ordering::Acquire) {
            uc.sleep_deadline_ns.store(0, Ordering::Release);
            uc.net_io_wait.store(false, Ordering::Release);
            if let Some(h) = sleep_handle.take() {
                narf_scheduler::narf_time::timer_wheel::cancel(h);
            }
            break;
        }
        // Resumed by the executor — loop and re-check the condition.
    }
}

/// Run `f` against a task's `UserTaskCtx`, resolved through the
/// refcounted task registry (`crate::task`). The returned `Arc<Task>`
/// keeps the ctx alive for the duration of `f` WITHOUT holding any
/// registry lock across the callback — the refcount, not a
/// deref-under-lock convention, is what makes this sound. Zombie
/// (exited-but-unreaped) tasks still resolve; poking their park state
/// is harmless and matches Linux's find-task-by-vpid semantics.
pub fn with_user_task_ctx<R>(task_id: u64, f: impl FnOnce(&UserTaskCtx) -> R) -> Option<R> {
    let t = crate::task::task_get(task_id)?;
    Some(f(&t.uctx))
}

// ── Polling-routine hooks ─────────────────────────────────────────
//
// A polling routine that lives outside this crate (typically the
// `UserTaskFuture::poll` body in a verification test or higher-
// level crate) registers a "what to do when the user yields /
// exits" hook here. The `Yield` and `ExitTask` syscall handlers
// consult these hooks; if a UserTaskCtx is installed AND a hook
// is registered, the handler stores the trap reason in
// `ctx.exit_reason` and tail-calls the hook (which does the
// `longjmp` back into the polling routine and never returns).
//
// Without a hook the handlers fall back to their pre-existing
// behaviour (Yield = Ok, ExitTask = `set_exit_landing` redirect).

type ExitHook = unsafe fn(*mut UserTaskCtx) -> !;

static YIELD_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static EXIT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static EXECVE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the `Yield`-from-user-mode hook. Call once at boot per
/// CPU's polling executor.
pub fn install_yield_hook(hook: ExitHook) {
    YIELD_HOOK.store(hook as *mut (), Ordering::Release);
}

/// Install the `ExitTask`-from-user-mode hook.
pub fn install_exit_hook(hook: ExitHook) {
    EXIT_HOOK.store(hook as *mut (), Ordering::Release);
}

/// Install the `Execve`-from-user-mode hook. Same shape as the
/// other hooks; longjmps the polling routine with
/// `EXIT_REASON_EXECVE` after the syscall handler has published
/// the new image's `ExecRequest` into `ctx.pending_exec`.
pub fn install_execve_hook(hook: ExitHook) {
    EXECVE_HOOK.store(hook as *mut (), Ordering::Release);
}

// ── Process/thread-exit observers ─────────────────────────────────
//
// Exit teardown splits by SCOPE, exactly as Linux splits per-task
// `do_exit` work from the `group_dead` process-wide work:
//
//   * THREAD-scoped observers fire for EVERY exiting thread, keyed on
//     its unique `tid` (clear_child_tid futex, the thread's fd-table
//     ref, per-task signal tables).
//   * PROCESS-scoped observers fire EXACTLY ONCE per thread group —
//     when its LAST live thread exits (Linux `group_dead =
//     atomic_dec_and_test(&signal->live)`). These do per-`pid`
//     teardown (parent SIGCHLD/wait4 reap, pidfd notify, cgroup
//     membership, per-pid IPC/FB resources). Running them once per
//     thread double-frees process-global state — that was the OCI
//     container-teardown #UD, where a multi-threaded exit_group ran
//     `release_pid` twice concurrently and scribbled this very
//     observer list (a corrupt `fn(u64,u64)` slot → ring-0 call to a
//     wild low address).
//
// Observers are append-only — there's no unregister. The intent is
// boot-time wiring, not runtime hot-swap. Both fan-outs run in plain
// kernel context (not the trap path) and may take spinlocks.

pub type ExitObserver = fn(pid: u64, tid: u64);

static THREAD_EXIT_OBSERVERS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<ExitObserver>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

static PROCESS_EXIT_OBSERVERS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<ExitObserver>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Register a THREAD-scoped exit callback — fires for every exiting
/// thread with `(pid, tid)`:
///   * `pid` — the user-visible thread-group id (shared by
///     `CLONE_THREAD` siblings).
///   * `tid` — the scheduler's `TaskId.raw()`, unique per thread;
///     per-thread bookkeeping (clear_child_tid, fd-table ref, signal
///     tables) keys on this.
pub fn register_thread_exit_observer(o: ExitObserver) {
    THREAD_EXIT_OBSERVERS.lock().push(o);
}

/// Register a PROCESS-scoped exit callback — fires exactly once, on the
/// `group_dead` transition (the last thread of `pid` to exit). `tid` is
/// that last thread's id; process teardown must key on `pid`, not `tid`
/// (the last thread need not be the group leader).
pub fn register_process_exit_observer(o: ExitObserver) {
    PROCESS_EXIT_OBSERVERS.lock().push(o);
}

/// Fan out the exit notification. Called by `UserTaskFuture::poll` (or
/// the own-stack exit path) when a task hits `EXIT_REASON_EXITED`. Also
/// exposed for test harnesses that drive the fan-out directly.
///
/// Every exiting thread runs the THREAD-scoped observers; the LAST
/// thread of the group additionally runs the PROCESS-scoped ones. The
/// `group_dead` decision is `thread_group_live_dec` — the atomic
/// decrement-and-test of the group's live-thread count (Linux
/// `signal->live`). Must be called EXACTLY ONCE per task exit, or the
/// count under/over-shoots.
pub fn notify_task_exited(pid: u64, tid: u64) {
    let thread = THREAD_EXIT_OBSERVERS.lock().clone();
    for o in thread.iter() {
        o(pid, tid);
    }
    let (group_dead, was_multithreaded) = crate::handlers::thread_group_live_dec_state(pid);
    if group_dead {
        let process = PROCESS_EXIT_OBSERVERS.lock().clone();
        for o in process.iter() {
            o(pid, tid);
        }
    }
    // CLONE_THREAD siblings are never wait4-reapable zombies. Their future
    // still owns an Arc until this poll returns, so the process registry can
    // drop its reference immediately after every exit observer has run.
    // The group leader remains registered through the ordinary process-zombie
    // window and is released when its parent reaps the shared PID.
    // Avoid a PID_TO_TASK registry lookup on the overwhelmingly common
    // single-threaded fork/exit path. Only a group that was ever tracked can
    // contain a non-leader task that needs this early release.
    if was_multithreaded {
        crate::handlers::release_exited_thread_task(pid, tid);
    }
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_clear_exit_observers() {
    THREAD_EXIT_OBSERVERS.lock().clear();
    PROCESS_EXIT_OBSERVERS.lock().clear();
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_clear_hooks() {
    YIELD_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    EXIT_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    clear_current();
}

/// Test-only reset of the execve hook (a test that installs its own
/// longjmp hook must not leave it behind for later execve tests).
#[doc(hidden)]
pub fn __test_clear_execve_hook() {
    EXECVE_HOOK.store(core::ptr::null_mut(), Ordering::Release);
}

// ── wait4 cooperative parking support ────────────────────────────────
//
// Two global tables coordinate the "parent parked in wait4" pattern:
//
//   WAIT_CHILD_CHECK_FN — a single registered fn(parent_id, want_pid,
//     status_ptr) -> i64 that tries to drain one entry from the parent's
//     pending-exits queue.  Returns the reaped child pid (> 0) on
//     success, or 0 if the queue is empty.  Registered at boot by
//     `handlers::wait_init`.  The fn must NOT take any lock that could
//     be held concurrently by a caller of `register_wait_child_waker`
//     (both run from the kernel-side polling path, single-CPU today).
//
//   WAIT_CHILD_WAKERS — per-task Waker slots stored when a task parks
//     in wait4.  `on_child_exit` in handlers.rs pulls the parent's slot
//     and calls wake() so the executor re-polls the task.
//
// Mirror of the `BYTE_RING_WAKER` pattern in narf-input.

/// fn(parent_id: u64, want_pid: i64, status_ptr: u64) -> i64
///   Returns reaped child pid (> 0) if a matching entry was drained
///   from the pending-exits queue, or 0 if the queue is empty.
pub type WaitChildCheckFn =
    fn(parent_id: u64, want_pid: i64, options: u32, out_status: *mut i32) -> i64;

static WAIT_CHILD_CHECK_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the wait4 reap-check callback.  Called once at boot by
/// `handlers::wait_init`.
pub fn register_wait_child_check(f: WaitChildCheckFn) {
    WAIT_CHILD_CHECK_FN.store(f as *mut (), Ordering::Release);
}

/// Invoke the registered check callback.  Returns 0 if no callback
/// is installed (test/fallback context without real wait4 tables).
pub fn call_wait_child_check(
    parent_id: u64,
    want_pid: i64,
    options: u32,
    out_status: *mut i32,
) -> i64 {
    let p = WAIT_CHILD_CHECK_FN.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    // SAFETY: p was stored by `register_wait_child_check` with a valid
    // WaitChildCheckFn; the static lifetime outlives any call.
    // SAFETY: Valid memory or trusted environment
    let f: WaitChildCheckFn = unsafe { core::mem::transmute(p) };
    f(parent_id, want_pid, options, out_status)
}

/// Per-task Waker slots for tasks parked in a blocking wait4.
/// Keyed by the parent task's pid (u64).  The slot is populated by
/// `UserTaskFuture::poll` when it finds `wait_child_pending = true`
/// and no reap is immediately available; it is consumed (wake called)
/// by `on_child_exit` in handlers.rs.
static WAIT_CHILD_WAKERS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, core::task::Waker>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the waker table (called once at boot alongside `wait_init`).
pub fn wait_child_waker_init() {
    *WAIT_CHILD_WAKERS.lock() = Some(alloc::collections::BTreeMap::new());
}

/// Store a waker for `parent_id`.  The waker fires when the parent's
/// child exits and `on_child_exit` is invoked.
pub fn register_wait_child_waker(parent_id: u64, waker: core::task::Waker) {
    let mut g = WAIT_CHILD_WAKERS.lock();
    if let Some(m) = g.as_mut() {
        m.insert(parent_id, waker);
    }
}

/// Take and wake the stored waker for `parent_id`, if any.  Called by
/// `on_child_exit` after pushing to the pending-exits queue.
pub fn wake_wait_child(parent_id: u64) {
    let waker = {
        let mut g = WAIT_CHILD_WAKERS.lock();
        g.as_mut().and_then(|m| m.remove(&parent_id))
    };
    if let Some(w) = waker {
        w.wake();
    }
}

/// Remove (drop, don't wake) the stored waker for `parent_id`.
/// Used by `UserTaskFuture::poll` when the double-check after
/// registering the waker finds a result — we clear the table slot
/// without scheduling a spurious re-poll.
pub fn drop_wait_child_waker(parent_id: u64) {
    let mut g = WAIT_CHILD_WAKERS.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&parent_id);
    }
}

/// Test-only: drain the waker table.
#[doc(hidden)]
pub fn __test_wait_child_waker_reset() {
    *WAIT_CHILD_WAKERS.lock() = Some(alloc::collections::BTreeMap::new());
}

#[inline]
pub(crate) fn yield_hook() -> Option<ExitHook> {
    let p = YIELD_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` is non-null and was stored by `install_yield_hook`
        // as `hook as *mut ()` from a real `ExitHook` fn pointer; the
        // round-trip back to `ExitHook` recovers the original fn ptr
        // (same ABI, pointer-sized).
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { core::mem::transmute::<*mut (), ExitHook>(p) })
    }
}

#[inline]
pub(crate) fn exit_hook() -> Option<ExitHook> {
    let p = EXIT_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` is non-null and was stored by `install_exit_hook`
        // as `hook as *mut ()` from a real `ExitHook` fn pointer; the
        // round-trip recovers the original fn ptr (same ABI,
        // pointer-sized).
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { core::mem::transmute::<*mut (), ExitHook>(p) })
    }
}

#[inline]
pub fn execve_hook() -> Option<ExitHook> {
    let p = EXECVE_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` is non-null and was stored by `install_execve_hook`
        // as `hook as *mut ()` from a real `ExitHook` fn pointer; the
        // round-trip recovers the original fn ptr (same ABI,
        // pointer-sized).
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { core::mem::transmute::<*mut (), ExitHook>(p) })
    }
}

// ── UserTaskFuture ────────────────────────────────────────────────
//
// The Stage-4 polling-future that lets a user-mode task ride the
// scheduler's ready queue. Each `poll`:
//   1. installs `&mut self.ctx` as the current user-task slot,
//   2. publishes `&mut self.jmp` via `CURRENT_JMP` so the static
//      yield/exit hooks (registered once at boot) can reach it,
//   3. snapshots kernel CR3 + clears IF,
//   4. setjmps. Returning 0 → enter or resume user mode (never
//      returns). Returning a non-zero longjmp value → a hook fired,
//      we map it to Yielded → Pending or Exited → Ready(()).
//
// The hooks are static fn pointers; both call `longjmp(CURRENT_JMP,
// reason)`. Single-CPU cooperative executor → exactly one task is
// in flight at any time → a single global `AtomicPtr<JmpBuf>` slot
// is sufficient. SMP bring-up will swap this for a per-CPU slot.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub use narf_scheduler::JmpBuf;

/// Stub `JmpBuf` for arches without a real implementation. The
/// arch-specific `JmpBuf` lives in
/// `narf_arch::<arch>::user_mode::JmpBuf` and is re-exported via
/// `narf_scheduler` for x86_64 / aarch64.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct JmpBuf {
    pub regs: [u64; 16],
}

/// Lifecycle stamp on a [`UserTaskFuture`]. `Initial` → first poll
/// will `enter_user_mode`; `Running` → re-poll will
/// `enter_user_mode_resume`; `Exited` → the future has reported
/// `Poll::Ready(())` and will not be polled again.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TaskState {
    Initial,
    Running,
    Exited,
}

/// Per-CPU current-jmpbuf slot. Set by `UserTaskFuture::poll` before
/// transitioning to user mode; consulted by the static yield/exit
/// hooks to find the polling routine to longjmp into. Cleared on
/// the trap-back path so a stale pointer can't be picked up by an
/// unrelated trap. Per-CPU because each CPU runs its own poller +
/// in-flight task, and a yielding task longjmps back into *its* CPU's
/// poll routine — the trap that drives the hook runs on the same CPU.
static CURRENT_JMP: [AtomicPtr<JmpBuf>; narf_lib::percpu::MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const NULL: AtomicPtr<JmpBuf> = AtomicPtr::new(core::ptr::null_mut());
    [NULL; narf_lib::percpu::MAX_CPUS]
};

/// This CPU's current-jmpbuf cell.
#[inline]
fn jmp_slot() -> &'static AtomicPtr<JmpBuf> {
    &CURRENT_JMP[narf_lib::percpu::current_cpu()]
}

#[cfg(target_arch = "x86_64")]
unsafe fn user_task_yield_hook(_uctx: *mut UserTaskCtx) -> ! {
    // The syscall handler already populated `*uctx.exit_reason` and
    // `*uctx.state` before tail-calling us. Our job is just to
    // longjmp back to the polling routine; the polling routine
    // reads `exit_reason` after setjmp returns non-zero.
    let p = jmp_slot().load(Ordering::Acquire);
    // SAFETY: the polling routine guarantees CURRENT_JMP points at
    // a live JmpBuf for the duration of the user-mode round-trip.
    // If a hook fires without a polling routine in flight, that's
    // a kernel bug — better to halt than to longjmp through a
    // dangling pointer.
    if p.is_null() {
        narf_scheduler::halt_forever();
    }
    // SAFETY: `p` is the non-null `JmpBuf` the in-flight polling
    // routine published in `CURRENT_JMP`; `longjmp` restores that
    // routine's setjmp context, which is live for the whole user-mode
    // round-trip. The null case is handled above.
    // SAFETY: Valid memory or trusted environment
    unsafe { narf_scheduler::longjmp(p as *const _, EXIT_REASON_YIELDED as u64) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn user_task_exit_hook(_uctx: *mut UserTaskCtx) -> ! {
    let p = jmp_slot().load(Ordering::Acquire);
    if p.is_null() {
        narf_scheduler::halt_forever();
    }
    // SAFETY: same as above.
    unsafe { narf_scheduler::longjmp(p as *const _, EXIT_REASON_EXITED as u64) }
}

/// Longjmp helper used by `sys_execve`: signals the polling
/// routine that the task is being re-imaged. The handler has
/// already published the new image's `ExecRequest` into
/// `ctx.pending_exec`; the polling routine reads it after
/// setjmp returns and swaps `process.address_space` /
/// `process.entry` / `process.stack_top` accordingly.
///
/// # Safety
///
/// Must be called only from the `Execve` syscall handler on the
/// in-flight task's trap path, with a live polling routine having
/// published its `JmpBuf` in `CURRENT_JMP` and the new image's
/// `ExecRequest` published in the task's `ctx.pending_exec`. The
/// caller must guarantee `CURRENT_JMP`'s setjmp context is still
/// valid. This function never returns — it longjmps into the poller.
#[cfg(target_arch = "x86_64")]
pub unsafe fn user_task_execve_hook(_uctx: *mut UserTaskCtx) -> ! {
    let p = jmp_slot().load(Ordering::Acquire);
    if p.is_null() {
        narf_scheduler::halt_forever();
    }
    // SAFETY: see exit_hook — CURRENT_JMP points at a live
    // JmpBuf for the duration of the user-mode round-trip.
    // SAFETY: Valid memory or trusted environment
    unsafe { narf_scheduler::longjmp(p as *const _, EXIT_REASON_EXECVE as u64) }
}

/// Wire the static yield + exit hooks into the syscall handlers'
/// hook slots. Idempotent — safe to call once at boot or on every
/// test setup; subsequent calls just re-store the same fn ptrs.
///
/// Without this call, `Yield` from a user task running under a
/// `UserTaskFuture` falls through to the legacy "Ok return" path
/// and `ExitTask` falls through to the `set_exit_landing` redirect,
/// neither of which gives the polling routine its longjmp back.
#[cfg(target_arch = "x86_64")]
pub fn install_user_task_hooks() {
    install_yield_hook(user_task_yield_hook);
    install_exit_hook(user_task_exit_hook);
    install_execve_hook(user_task_execve_hook);
    // Own-stack user-CPU accounting: slices end at kernel_switch yields
    // (yield_current_stackful), never through this poll's fold — without
    // the hook every own-stack task reports utime 0 (getrusage / times /
    // ps TIME / `time`'s user column, per the alpine probe).
    narf_scheduler::stackful::set_user_slice_account_hook(crate::handlers::account_user_cpu_ns);
    #[cfg(feature = "linux-compat")]
    narf_scheduler::stackful::set_user_perf_switch_hook(crate::perf_event::on_task_switch);
    // Per-task-own-stack model: flips a trap/syscall from a user task onto that
    // task's OWN kernel stack with preemption via a clean kernel_switch
    // (try_preempt_user), retiring the longjmp-out-of-trap-handler path.
    //
    // STATUS 2026-06-26: DEFAULT (ON). Validated on x86_64: boot-smoke clean,
    // kernel-test 5878 pass / 0 fail, the whole interactive system runs
    // (init→getty→shell→redis→netserve), stress-ng fork/exec/memcpy churn
    // survives (12+ rounds) — and it retires the longjmp model's intractable
    // stress-ng rip=0x3 executor-dispatch crash. A long list of own-stack bugs
    // were fixed to get here: the by-value wheel-drain array smash; CR3/EXEC_CTX/
    // CURRENT_STACKFUL_TASK/rsp0 clobber across NESTED poll_to_yield; the
    // all-parked fire_due wheel-service gap; the ns_to_cycles park deadline; and
    // the cross-task UserTaskCtx clobber (current_user_task resolved the wrong
    // task after a kernel_switch resume — fixed by resolving via the executor
    // slot id). KNOWN FOLLOW-UP: net-smoke is ~4/5 — an occasional virtio-net/
    // SLIRP inbound-delivery race (the guest NIC receives no frames post-connect
    // in the failing runs), host-side networking timing, tracked separately.
    if true {
        narf_scheduler::stackful::enable_user_own_stack();
    }
}

/// Per-task x87/SSE register file for `FXSAVE`/`FXRSTOR`.
///
/// The kernel is built `+soft-float,-sse`, so it never reads or writes
/// XMM / x87 registers — but USER tasks do (musl/busybox `memcpy` /
/// `memset` / string ops are SSE). The user-task `UserState` snapshot
/// only carries GPRs, so across a *preemptive* trap (timer IRQ) a
/// task's live XMM state is left in the hardware registers and then
/// clobbered by whatever user task the executor polls next. A task
/// preempted mid-`memcpy` would resume with another task's XMM and
/// write garbage — observed as a NULL-deref in musl `free()`'s bin
/// unlink after a torn heap write, and (under user-task migration,
/// where the resuming CPU's XMM are guaranteed to differ) the dominant
/// cause of the busybox-pipe flake. `FXSAVE` on the way out of user
/// mode and `FXRSTOR` on the way back in preserves it per task.
///
/// [`FPU_AREA_SIZE`](narf_arch::x86_64::xsave::FPU_AREA_SIZE) bytes, 64-byte
/// aligned per the `XSAVE`/`XRSTOR` memory-operand alignment requirement (also
/// satisfies `FXSAVE`'s 16-byte requirement for the fallback path). Sized for
/// the full boot-enabled state (x87+SSE+AVX+AVX-512+PKRU), not just the
/// 512-byte `FXSAVE` legacy region — so AVX/AVX-512 (`zmm`) register state is
/// preserved across preemption + migration.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(64))]
struct FpuArea([u8; narf_arch::x86_64::xsave::FPU_AREA_SIZE]);

#[cfg(target_arch = "x86_64")]
impl FpuArea {
    /// A canonical reset FPU image used for a task's first entry:
    /// `FCW = 0x037F` (all x87 exceptions masked, 64-bit precision),
    /// `MXCSR = 0x1F80` (all SSE exceptions masked). Everything else
    /// zero — including the `XSAVE` header at offset 512 (`XSTATE_BV = 0`,
    /// `XCOMP_BV = 0`), so a standard `XRSTOR` re-inits every component and
    /// still loads `MXCSR`/`FCW` from the legacy region. An all-zero legacy
    /// area would restore `MXCSR = 0` (SSE exceptions UNmasked), so the first
    /// denormal/inexact in user SSE would raise a spurious `#XF` — hence the
    /// two control words are seeded explicitly.
    /// Heap-first construction of the reset image. A by-value
    /// `FpuArea` return would materialise a 4 KiB temporary on the
    /// caller's kernel stack — the exact frame bloat that overflowed
    /// the 16 KiB own-stack in `sys_fork` (see the `fpu` field doc);
    /// zero-allocating the Box and poking the two control words in
    /// place keeps every frame small.
    fn reset_boxed() -> alloc::boxed::Box<Self> {
        let layout = core::alloc::Layout::new::<Self>();
        // SAFETY: `FpuArea` is a plain `[u8; N]` wrapper — the all-zero
        // bit pattern is a valid value — and `layout` is its exact
        // (non-zero-size, 64-aligned) layout, so a zeroed allocation of
        // it is a fully-initialized `FpuArea` the Box may own.
        let mut b = unsafe {
            let p = alloc::alloc::alloc_zeroed(layout) as *mut Self;
            if p.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            alloc::boxed::Box::from_raw(p)
        };
        b.0[0] = 0x7F; // FCW byte 0
        b.0[1] = 0x03; // FCW byte 1  → 0x037F
        b.0[24] = 0x80; // MXCSR byte 0
        b.0[25] = 0x1F; // MXCSR byte 1 → 0x1F80
        b
    }
}

/// Polling future that drives a user-mode process to completion via
/// the scheduler's ready queue. Construct with [`UserTaskFuture::new`]
/// and spawn via `narf_scheduler::spawn_user`.
///
/// Each `poll` performs the setjmp/longjmp dance described in the
/// module-level docs. The future returns `Pending` on every
/// cooperative yield (`EXIT_REASON_YIELDED`) and `Ready(())` on
/// `EXIT_REASON_EXITED`.
#[cfg(target_arch = "x86_64")]
pub struct UserTaskFuture {
    process: crate::UserProcess,
    /// The refcounted task object (registered in `crate::task::TASKS`
    /// at spawn). The future's clone keeps `task.uctx` alive for as
    /// long as the executor can possibly run this task, so every raw
    /// `*mut UserTaskCtx` the trap/park paths publish stays valid even
    /// if the task is concurrently reaped by its parent.
    task: alloc::sync::Arc<crate::task::Task>,
    jmp: UnsafeCell<JmpBuf>,
    state: TaskState,
    /// Snapshot of the kernel's CR3 captured on the first poll so
    /// we can restore it on the return path. `None` until the first
    /// poll runs.
    saved_cr3: core::cell::Cell<Option<u64>>,
    /// Timer-wheel slot this task is parked on while sleeping
    /// (`sys_sleep`/`nanosleep` with a finite deadline). The poll
    /// registers the slot once and refreshes it across spurious
    /// re-polls instead of self-waking every 1ms; the wheel fires the
    /// task's waker at the deadline. Cleared (cancelled) on wake.
    sleep_handle: Option<narf_scheduler::narf_time::timer_wheel::SleepHandle>,
    /// This task's saved x87/SSE register file. `FXRSTOR`'d before
    /// every entry into user mode and `FXSAVE`'d on every trap-return,
    /// so the task's XMM/x87 state survives preemption + migration.
    /// See [`FpuArea`].
    ///
    /// Boxed, NOT inline: `UserTaskFuture` and `PendingUserProcess`
    /// travel by value through `sys_fork` / `do_clone3` / the spawn
    /// helpers, and an inline 4 KiB `FpuArea` multiplied into ~14 KiB
    /// of inlined stack frame in `sys_fork` — which overflowed the
    /// 16 KiB per-task own kernel stack into the heap below it (the
    /// wl_xdg slab free-block canary corruption). The Box keeps the
    /// future a small struct; the FPU image lives on the heap.
    fpu: alloc::boxed::Box<FpuArea>,
}

#[cfg(target_arch = "x86_64")]
impl core::fmt::Debug for UserTaskFuture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserTaskFuture")
            .field("pid", &self.process.pid)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(target_arch = "x86_64")]
// SAFETY: the future is polled only on a single CPU at a time
// (single-CPU cooperative executor); the UnsafeCell-wrapped JmpBuf
// is only written by `poll` (between the install_current and the
// setjmp) and only read by the longjmp targeting it. The hooks
// reach it via the global CURRENT_JMP atomic, so cross-thread
// publication is the atomic, not the cell. The future never escapes
// the executor's `Pin<Box<...>>`.
unsafe impl Send for UserTaskFuture {}

#[cfg(target_arch = "x86_64")]
impl UserTaskFuture {
    /// Construct a fresh polling future for `process`, bound to its
    /// pre-registered refcounted `task` (see
    /// `crate::task::Task::new_registered`). The future is not yet on
    /// any ready queue — hand it to `narf_scheduler::spawn_user`
    /// under the same reserved `TaskId`.
    pub fn new(process: crate::UserProcess, task: alloc::sync::Arc<crate::task::Task>) -> Self {
        Self {
            process,
            task,
            jmp: UnsafeCell::new(JmpBuf::default()),
            state: TaskState::Initial,
            saved_cr3: core::cell::Cell::new(None),
            sleep_handle: None,
            fpu: FpuArea::reset_boxed(),
        }
    }

    /// Construct a polling future seeded with a pre-populated
    /// `UserState`. The first poll calls `enter_user_mode_resume`
    /// instead of `enter_user_mode(entry, rsp)`, so the task wakes
    /// up at the saved (rip, rsp) with all GPRs / RFLAGS restored
    /// from `state` rather than at `process.entry` / `process.stack_top`.
    ///
    /// Used by `sys_fork`: the child inherits the parent's trap-
    /// frame snapshot with `rax` rewritten to 0 so user code reads
    /// the POSIX "child got 0 from fork()" return value when its
    /// `int 0x80` returns. The `process.entry` / `process.stack_top`
    /// fields on the parent's `UserProcess` aren't consulted here —
    /// they're only meaningful for the load-time path.
    pub fn resume_with(
        process: crate::UserProcess,
        task: alloc::sync::Arc<crate::task::Task>,
        state: UserState,
    ) -> Self {
        // SAFETY: the task was just registered and has never been
        // enqueued — no other CPU can touch its `uctx` yet, so the
        // cell write cannot race.
        unsafe {
            *task.uctx.state.get() = state;
        }
        Self {
            process,
            task,
            jmp: UnsafeCell::new(JmpBuf::default()),
            // Skip `Initial` so the first poll takes the
            // `enter_user_mode_resume` arm and walks the saved
            // state instead of the (entry, stack_top) pair.
            state: TaskState::Running,
            saved_cr3: core::cell::Cell::new(None),
            sleep_handle: None,
            // A `fork(2)` child resumes immediately after the `int 0x80`
            // that issued the clone — XMM/x87 are caller-saved across the
            // syscall per the SysV ABI, so a canonical reset image (not
            // the parent's live FPU) is the correct seed.
            fpu: FpuArea::reset_boxed(),
        }
    }

    /// Borrow the inner process — useful for inspection from tests.
    pub fn process(&self) -> &crate::UserProcess {
        &self.process
    }

    /// Inspect the current lifecycle stamp.
    pub fn task_state(&self) -> TaskState {
        self.state
    }
}

#[cfg(target_arch = "x86_64")]
impl core::future::Future for UserTaskFuture {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        // Slot 17: UserTaskFuture::poll heartbeat. Toggles each
        // poll. If this toggles but no shell prompt, the executor
        // IS polling user tasks but they're not running their
        // user-mode code (stuck in trap/return path). If it never
        // toggles, the executor isn't reaching user task slots at
        // all.
        // (Slot 17 user-task heartbeat lives in the scheduler,
        // before activate(). A beacon here would page-fault: this
        // body runs with the user AS active, which lacks the low-
        // half identity map that the FB phys lives in.)
        // Pin guarantees we're not moved between polls. We need
        // &mut access to the inner struct so the hooks see a stable
        // address for `self.ctx` and `self.jmp`.
        // SAFETY: we don't move out of the Pin; we only project &mut
        // to fields whose address stability we own.
        // SAFETY: Valid memory or trusted environment
        let this = unsafe { self.get_unchecked_mut() };

        if this.state == TaskState::Exited {
            // Defensive — the executor drops Ready slots, so this
            // shouldn't be reached, but if a future somehow gets
            // re-polled after Ready it stays Ready.
            return core::task::Poll::Ready(());
        }

        // Job-control stop: a task halted by SIGSTOP/SIGTSTP/SIGTTIN/
        // SIGTTOU stays parked — never re-entering user mode — until
        // SIGCONT clears its stopped flag and fires the signal waker.
        // SIGKILL still breaks through so a stop can't make a task
        // un-killable. We register the signal waker (consumed +
        // fired by `wake_signal`) and return Pending without a
        // wake_by_ref, so the task truly idles until woken.
        {
            let tp = crate::handlers::current_task_id();
            if crate::handlers::is_task_stopped(tp)
                && (crate::handlers::signal_pending_bits(tp) & (1 << 9)) == 0
            {
                crate::handlers::register_signal_waker(tp, cx.waker().clone());
                return core::task::Poll::Pending;
            }
        }

        // sys_sleep parks the task by stashing an absolute deadline
        // here and longjmp'ing back. Until the deadline fires,
        // re-poll without re-entering user mode — that gives the
        // executor a chance to round-robin other ready tasks
        // (kernel async work, other user tasks) instead of
        // burning the CPU inside an iretq loop.
        //
        // Throttle: pure `wake_by_ref()` re-poll burns the executor
        // hot — every round visits every slot, so a 5-second user
        // sleep in a tight `puts+sleep` loop generates millions of
        // poll round-trips and surfaced as a heap OOM in practice
        // (some allocator path on the way to/from each visit).
        // Busy-wait a small fixed chunk here, ticking the sleep
        // pumps so kernel async tasks still make forward progress,
        // then return Pending. The scale is tuned for ~1 ms per
        // park iteration: short enough not to perturb other tasks,
        // long enough to keep heap pressure flat.
        let deadline = this.task.uctx.sleep_deadline_ns.load(Ordering::Acquire);
        if deadline != 0 {
            // Watchdog liveness signal (see `UserTaskCtx::dbg_park_checks`).
            this.task
                .uctx
                .dbg_park_checks
                .fetch_add(1, Ordering::Relaxed);
            let now = narf_scheduler::narf_time::monotonic_ns();
            // An asynchronously-raised signal (e.g. SIGALRM from an
            // interval timer, a cross-process kill) must break ANY park —
            // finite deadlines included: nanosleep/futex/poll are signal-
            // interruptible on Linux (-EINTR). The old `deadline ==
            // u64::MAX` restriction (guarding against a busy-spin on a
            // pending *ignored* signal) is obsolete: the return-to-user
            // delivery path consumes SIG_IGN/default-Ignore pending bits,
            // so the break costs one spurious re-execution at most. A
            // finite-deadline park that ignored signals was a de-facto
            // permanent strand when the deadline was far out (the
            // stress-ng --futex SMP hang).
            let signal_pending =
                crate::handlers::is_signal_pending(crate::handlers::current_task_id());
            if now < deadline && !signal_pending {
                // rt_sigtimedwait park: same register-then-re-check shape as
                // the own-stack `park_should_block` sigwait arm — register in
                // SIGNAL_WAKERS (every raise path fires it via `wake_signal`)
                // and break the park when a signal in the waited set (mask
                // ignored) or any deliverable signal is pending; the rewound
                // syscall re-executes and consumes / returns -EINTR.
                let sw = this.task.uctx.sigwait_set.load(Ordering::Acquire);
                if sw != 0 {
                    let tid = crate::handlers::current_task_id();
                    crate::handlers::register_signal_waker(tid, cx.waker().clone());
                    if crate::handlers::sigwait_should_wake(tid, sw) {
                        crate::handlers::drop_signal_waker(tid);
                        this.task.uctx.sleep_deadline_ns.store(0, Ordering::Release);
                        this.task.uctx.sigwait_set.store(0, Ordering::Release);
                        cx.waker().wake_by_ref();
                        return core::task::Poll::Pending;
                    }
                } else {
                    // Non-sigwait park — release the sticky waiter
                    // reservation (see `UserTaskCtx::sigwait_reserve`).
                    this.task.uctx.sigwait_reserve.store(0, Ordering::Release);
                    // Signal-interruptible park: register in SIGNAL_WAKERS
                    // FIRST (every raise path fires it via `wake_signal`),
                    // then RE-CHECK pending — closes the check→register
                    // window; see the own-stack `park_should_block` twin.
                    let tid = crate::handlers::current_task_id();
                    crate::handlers::register_signal_waker(tid, cx.waker().clone());
                    if crate::handlers::is_signal_pending(tid) {
                        crate::handlers::drop_signal_waker(tid);
                        this.task.uctx.sleep_deadline_ns.store(0, Ordering::Release);
                        if let Some(h) = this.sleep_handle.take() {
                            narf_scheduler::narf_time::timer_wheel::cancel(h);
                        }
                        cx.waker().wake_by_ref();
                        return core::task::Poll::Pending;
                    }
                }
                // Parking on a blocking wait. If `sys_epoll_wait`/
                // `sys_poll` flagged this as a net I/O wait, register
                // our waker so inbound TCP data wakes us immediately
                // (crate::handlers::wake_io_waiters via the net
                // readiness hook) instead of waiting out the deadline.
                if this.task.uctx.net_io_wait.load(Ordering::Acquire) {
                    crate::handlers::register_io_waiter(
                        crate::handlers::current_task_id(),
                        cx.waker().clone(),
                    );
                    // The global readiness generation is advisory, not a
                    // readiness predicate for this task's interest set. Keep
                    // the waiter parked after refreshing it; a true missed
                    // source wake is retried by the I/O backstop instead of
                    // making unrelated activity spin epoll/poll in userspace.
                    refresh_io_wait_generation_after_registration(
                        &this.task.uctx,
                        narf_net::readiness::generation(),
                    );
                    let encoded_epfd = this.task.uctx.epoll_wait_fd.load(Ordering::Acquire);
                    if encoded_epfd != 0
                        && crate::epoll::epoll_fd_has_ready(
                            crate::handlers::current_task_id(),
                            (encoded_epfd - 1) as u32,
                        )
                    {
                        crate::handlers::drop_io_waiter(crate::handlers::current_task_id());
                        this.task.uctx.sleep_deadline_ns.store(0, Ordering::Release);
                        cx.waker().wake_by_ref();
                        return core::task::Poll::Pending;
                    }
                }
                // FUTEX_WAIT: `sys_futex` published the futex word here.
                // Register our waker on the per-uaddr wait queue so a
                // `FUTEX_WAKE` on that word wakes us promptly (a real blocking
                // futex). Same lost-wakeup guard as net I/O: if the per-uaddr
                // wake counter advanced since the syscall's snapshot, a wake
                // raced us — clear the park and self-wake to re-enter user
                // mode (musl re-checks the word) instead of sleeping it out.
                let fu = this.task.uctx.futex_uaddr.load(Ordering::Acquire);
                if fu != 0 {
                    let key = crate::handlers::futex_key(
                        this.task.uctx.futex_namespace.load(Ordering::Acquire),
                        fu,
                    );
                    crate::handlers::futex_register_waiter_key(
                        key,
                        crate::handlers::current_task_id(),
                        cx.waker().clone(),
                    );
                    // Same stay-parked decision as the own-stack park loop:
                    // gen guard for a racing FUTEX_WAKE plus the futex-word
                    // re-validation that keeps a wakeless word rewrite
                    // (musl condvar requeue handoff, robust-owner death)
                    // from re-parking this task forever.
                    let stay = crate::handlers::futex_park_should_stay(
                        crate::handlers::futex_gen_key(key),
                        this.task.uctx.futex_park_gen.load(Ordering::Acquire),
                        crate::handlers::futex_read_user_word(fu),
                        this.task.uctx.futex_val.load(Ordering::Acquire),
                    );
                    if !stay {
                        crate::handlers::futex_drop_waiter_key(
                            key,
                            crate::handlers::current_task_id(),
                        );
                        this.task.uctx.sleep_deadline_ns.store(0, Ordering::Release);
                        this.task.uctx.futex_uaddr.store(0, Ordering::Release);
                        this.task.uctx.futex_namespace.store(0, Ordering::Release);
                        cx.waker().wake_by_ref();
                        return core::task::Poll::Pending;
                    }
                }
                if deadline == u64::MAX {
                    // Infinite park (pause / blocking poll/epoll/futex wait).
                    // Earlier this BUSY-SPUN for 1 ms per poll running the
                    // sleep pumps, then self-woke. That had two bad effects
                    // under a real HLT-ing executor (KVM): (1) the 1 ms spin
                    // charged a full burst against the fair-share budget every
                    // poll, so an I/O-bound task (epoll-parked redis) looked
                    // like a CPU hog and got Throttled — after which only an
                    // external wake, NOT the timer tick, could revive it, so a
                    // single lost readiness wake wedged it permanently; and
                    // (2) the self-wake tick-paced its re-poll, gating off-box
                    // round-trips at ~16.7 ms. Instead, PARK on the timer wheel
                    // with a one-tick fallback deadline: the real wake is the
                    // io-waiter / futex / signal wake (now re-polled PROMPTLY
                    // by the scheduler's EXTERNAL_WAKE fast-repoll), and the
                    // wheel slot is just a lost-wake / pending-signal safety
                    // net that bounds the worst case to ~one tick. sleep_pumps
                    // still run in the executor's own idle path every round.
                    const FALLBACK_NS: u64 = 10_000_000; // ~1 tick (100 Hz)
                    let fallback_cycles =
                        narf_scheduler::narf_time::ns_to_cycles(now.saturating_add(FALLBACK_NS));
                    // `refresh_waker_at` — keep the slot's fire time current
                    // across parks that reuse this handle (a stale earlier
                    // deadline would pin the backstop; see park_should_block).
                    let refreshed = this.sleep_handle.is_some_and(|h| {
                        narf_scheduler::narf_time::timer_wheel::refresh_waker_at(
                            h,
                            fallback_cycles,
                            cx.waker().clone(),
                        )
                    });
                    if !refreshed {
                        this.sleep_handle = narf_scheduler::narf_time::timer_wheel::register(
                            fallback_cycles,
                            cx.waker().clone(),
                        )
                        .ok();
                        if this.sleep_handle.is_none() {
                            // Wheel full / no arm callback: self-wake so the
                            // task still makes progress (degraded, never wedged).
                            cx.waker().wake_by_ref();
                        }
                    }
                    return core::task::Poll::Pending;
                }
                // Finite sleep (sys_sleep / nanosleep): PARK on the timer
                // wheel instead of self-waking. The wheel fires our waker at
                // the deadline (via the timer IRQ → take_due → deferred_wake,
                // or the executor idle path's fire_due fallback), so the
                // executor can round-robin other tasks / idle instead of
                // re-polling us every 1ms. Register once; refresh across any
                // spurious re-poll so we never leak a slot.

                // Finite io-wait park: clamp the wheel fire to a ~10ms lost-wake
                // backstop (same rationale as `park_fire_deadline_ns` in the
                // own-stack path) so a lost cross-core io-wake self-heals in
                // ~10ms instead of stranding until a long finite deadline.
                let fire_ns = park_fire_deadline_ns(
                    deadline,
                    now,
                    this.task.uctx.net_io_wait.load(Ordering::Acquire),
                );
                let deadline_cycles = narf_scheduler::narf_time::ns_to_cycles(fire_ns);
                // `refresh_waker_at` — see the infinite-park note above.
                let refreshed = this.sleep_handle.is_some_and(|h| {
                    narf_scheduler::narf_time::timer_wheel::refresh_waker_at(
                        h,
                        deadline_cycles,
                        cx.waker().clone(),
                    )
                });
                if !refreshed {
                    this.sleep_handle = narf_scheduler::narf_time::timer_wheel::register(
                        deadline_cycles,
                        cx.waker().clone(),
                    )
                    .ok();
                    if this.sleep_handle.is_none() {
                        // Wheel full or no arm callback: fall
                        // back to a self-wake so the task still makes
                        // progress (degraded, never wedged).
                        cx.waker().wake_by_ref();
                    }
                }
                return core::task::Poll::Pending;
            }
            // Deadline reached or a signal is pending — clear so the next
            // sys_sleep call doesn't see stale state, cancel any wheel slot,
            // then fall through to the normal resume path (which re-enters
            // user mode; a pending signal is delivered on the next return).
            // Drop any signal-waker entry this park registered (no-op if
            // `wake_signal` already consumed it when it fired us).
            crate::handlers::drop_signal_waker(crate::handlers::current_task_id());
            this.task.uctx.sleep_deadline_ns.store(0, Ordering::Release);
            this.task.uctx.net_io_wait.store(false, Ordering::Release);
            this.task.uctx.futex_uaddr.store(0, Ordering::Release);
            this.task.uctx.sigwait_set.store(0, Ordering::Release);
            if let Some(h) = this.sleep_handle.take() {
                narf_scheduler::narf_time::timer_wheel::cancel(h);
            }
        }

        // sys_wait4 cooperative parking: when a blocking wait4 finds
        // no exited child yet, it sets `wait_child_pending = true`
        // and longjmps back here.  We try to reap first; if that
        // fails we store our waker (so `on_child_exit` can fire it)
        // and return `Pending` — NO `wake_by_ref`, so the task truly
        // parks until the waker fires.  On re-poll after the wake,
        // the reap should succeed and we write the result into the
        // saved UserState.rax before falling through to re-enter
        // user mode.
        if this.task.uctx.wait_child_pending.load(Ordering::Acquire) {
            let want_pid = this.task.uctx.wait_child_want_pid.load(Ordering::Acquire);
            let wait_options = this.task.uctx.wait_child_options.load(Ordering::Acquire);
            let status_ptr = this.task.uctx.wait_child_status_ptr.load(Ordering::Acquire);
            // Use the scheduler TaskId (set by CURRENT_TASK before this poll)
            // as the key to look up PENDING_EXITS. `sys_fork` stores the
            // parent's TaskId (`current_task_id()`) into PARENT_OF and
            // PENDING_EXITS, so the lookup key must also be the TaskId.
            let task_pid = crate::handlers::current_task_id();
            let mut child_status = 0i32;
            let reaped = call_wait_child_check(task_pid, want_pid, wait_options, &mut child_status);
            if reaped > 0 {
                // Reap succeeded — write the wstatus (wait4) or
                // siginfo_t (waitid) to the user pointer and put the
                // syscall result (reaped pid for wait4, 0 for waitid)
                // into the saved RAX, then clear the pending flags.
                let is_waitid = this.task.uctx.wait_child_is_waitid.load(Ordering::Acquire);
                let rax =
                    crate::handlers::finish_wait_child(status_ptr, is_waitid, reaped, child_status);
                // SAFETY: `state.get()` is the `*mut UserState` (== `*mut
                // narf_scheduler::UserState`) backing this future's saved
                // frame; we own it (Pin-stable) and no other handle
                // aliases it here.
                unsafe {
                    #[cfg(target_arch = "x86_64")]
                    {
                        let us = &mut *this.task.uctx.state.get();
                        us.rax = rax;
                    }
                }
                this.task
                    .uctx
                    .wait_child_pending
                    .store(false, Ordering::Release);
                this.task
                    .uctx
                    .wait_child_is_waitid
                    .store(false, Ordering::Release);
                // Fall through to re-enter user mode with the result.
            } else {
                // No child has exited yet — register our waker so
                // `on_child_exit` can wake us, then park.
                // Double-check after registering (race: child exits
                // between the reap check above and registering here).
                register_wait_child_waker(task_pid, cx.waker().clone());
                let mut child_status2 = 0i32;
                let reaped2 =
                    call_wait_child_check(task_pid, want_pid, wait_options, &mut child_status2);
                if reaped2 > 0 {
                    // Child exited in the window — remove the waker
                    // we just stored (no spurious self-wake needed),
                    // write the result, clear pending, fall through.
                    drop_wait_child_waker(task_pid);
                    let is_waitid = this.task.uctx.wait_child_is_waitid.load(Ordering::Acquire);
                    let rax = crate::handlers::finish_wait_child(
                        status_ptr,
                        is_waitid,
                        reaped2,
                        child_status2,
                    );
                    // SAFETY: `state.get()` is the `*mut UserState`
                    // backing this future's saved frame; we own it
                    // (Pin-stable) and no other handle aliases it in
                    // this scope.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        #[cfg(target_arch = "x86_64")]
                        {
                            let us = &mut *this.task.uctx.state.get();
                            us.rax = rax;
                        }
                    }
                    this.task
                        .uctx
                        .wait_child_pending
                        .store(false, Ordering::Release);
                    this.task
                        .uctx
                        .wait_child_is_waitid
                        .store(false, Ordering::Release);
                    // Fall through to re-enter user mode.
                } else {
                    // Truly no child yet. wait4 is signal-interruptible
                    // (Linux): register a SIGNAL waker so an asynchronously
                    // raised signal — e.g. the parent's own ITIMER_REAL
                    // SIGALRM that stops its workers, fired from the timer
                    // tick while we park here — wakes us even though no child
                    // has exited. If a deliverable signal is already pending,
                    // abandon the wait with EINTR: bake -EINTR into the saved
                    // frame, clear the wait state, and fall through to
                    // re-enter user mode, where the delivery hook runs the
                    // handler and the syscall returns -EINTR (musl's waitpid
                    // loop re-issues the wait, which then reaps). Without this
                    // a parent blocked in wait4 while CPU-bound children spin
                    // never takes its SIGALRM — the SMP chroot_run/stress-ng
                    // hang.
                    crate::handlers::register_signal_waker(task_pid, cx.waker().clone());
                    if crate::handlers::has_interrupting_signal(task_pid) {
                        drop_wait_child_waker(task_pid);
                        // SAFETY: `state.get()` is the `*mut UserState` backing
                        // this future's saved frame; we own it (Pin-stable) and
                        // no other handle aliases it here.
                        unsafe {
                            #[cfg(target_arch = "x86_64")]
                            {
                                let us = &mut *this.task.uctx.state.get();
                                us.rax = (-4i64) as u64; // -EINTR
                            }
                        }
                        this.task
                            .uctx
                            .wait_child_pending
                            .store(false, Ordering::Release);
                        this.task
                            .uctx
                            .wait_child_is_waitid
                            .store(false, Ordering::Release);
                        // Fall through to re-enter user mode (delivers SIGALRM).
                    } else {
                        // Truly park until `on_child_exit` or `wake_signal`
                        // fires our waker.  Do NOT call wake_by_ref here.
                        return core::task::Poll::Pending;
                    }
                }
            }
        }

        // Console blocking-read park: sys_read found the input ring empty
        // and rewound RIP to re-execute the read on resume. Register our
        // waker so the serial/keyboard IRQ (push_global → BYTE_RING_WAKER →
        // deferred_wake) reschedules us. If a byte is already available
        // (raced in, or this is the wake), clear the flag and fall through
        // to re-enter user mode so the read re-runs and drains it. Else
        // return Pending with NO wake_by_ref — the task truly idles until a
        // keystroke, so the executor can halt instead of busy-polling.
        if this.task.uctx.console_read_pending.load(Ordering::Acquire) {
            narf_input::register_byte_waker(cx.waker());
            // pending_input() (serial bytes + keyboard keys), not
            // pending_bytes() — the unified discipline drains both rings,
            // so a keystroke alone must un-park a blocked console read.
            if narf_input::pending_input() > 0 {
                this.task
                    .uctx
                    .console_read_pending
                    .store(false, Ordering::Release);
                // fall through to resume + re-execute the read
            } else {
                return core::task::Poll::Pending;
            }
        }

        // (Task registration happens at spawn time — `crate::task::
        // Task::new_registered` runs before the slot is enqueued, so
        // the task is resolvable from its very first instruction.)

        // Snapshot kernel CR3 EVERY poll, not once. The kernel
        // root can shift between polls — when the page allocator
        // hands out a phys-frame that was previously a PML4 page
        // (e.g. a freed init/shell user-AS root) for a fresh user
        // mmap, the OLD PML4 page contents get overwritten and
        // restoring to that phys triple-faults. The scheduler
        // already does a per-poll save/restore around the call
        // (`scheduler/src/lib.rs:1357`), so the CR3 we read here
        // is whatever it just handed us — guaranteed live for at
        // least the duration of this poll body. Cache it in
        // `saved_cr3` for the post-trap-back restore.
        {
            let cr3: u64;
            // SAFETY: reading CR3 has no side effects.
            unsafe {
                core::arch::asm!("mov {v}, cr3", v = out(reg) cr3,
                    options(nostack, preserves_flags));
            }
            this.saved_cr3.set(Some(cr3));
        }

        // Publish the per-task pointers the trap handler + hooks
        // need. The hooks dereference `current_user_task()` to find
        // the UserTaskCtx; CURRENT_JMP gives them this future's
        // JmpBuf to longjmp through. Stored before any state
        // transition so a trap that lands mid-setup still finds
        // valid slots.
        install_current(&this.task.uctx as *const UserTaskCtx as *mut UserTaskCtx);
        jmp_slot().store(this.jmp.get(), Ordering::Release);

        // Activate the user AS. `addr_space.activate()` does the
        // MOV CR3 on x86_64.
        let _ = this.process.address_space.activate();

        // Own-stack model: publish the just-loaded CR3 so the scheduler can
        // re-activate this AS on every kernel_switch resume (preempt/park) —
        // the poll runs only ONCE, so this is the sole point that records it.
        #[cfg(target_arch = "x86_64")]
        if narf_scheduler::stackful::user_own_stack_enabled() {
            let cr3: u64;
            // SAFETY: Reading the current CPU's CR3 register has no side-effects.
            unsafe {
                core::arch::asm!("mov {v}, cr3", v = out(reg) cr3,
                    options(nostack, nomem, preserves_flags));
            }
            narf_scheduler::stackful::set_current_user_cr3(cr3);
        }

        // Program the per-task TLS thread pointer. Done after CR3
        // is in place — `IA32_FS_BASE` doesn't depend on the
        // page-table root, but pairing the writes here keeps the
        // "this batch of MSRs reflects the outgoing user task"
        // mental model intact. Skipped when the binary has no
        // PT_TLS (`fs_base = None`), in which case the previous
        // task's FS base is left in place; the user code wouldn't
        // dereference `fs:` if its image declared no TLS.
        // arch_prctl-set override takes precedence over the
        // load-time process.fs_base. Without this, a user-mode
        // `arch_prctl(ARCH_SET_FS, ...)` would only stick until
        // the next preempting trap re-entered the poll body —
        // ld-musl, which does ARCH_SET_FS early in
        // `__init_libc`, would then read a stale FS_BASE and
        // SIGSEGV on the next TCB-pointer access.
        let override_fs = this.task.uctx.pending_fs_base.load(Ordering::Acquire);
        let effective_fs = if override_fs != u64::MAX {
            Some(override_fs)
        } else {
            this.process.fs_base
        };
        if let Some(fs_base) = effective_fs {
            // SAFETY: writing IA32_FS_BASE is unconditional at
            // CPL=0 long-mode; `fs_base` is a canonical user vaddr
            // (came from `stage_tls` or arch_prctl).
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_scheduler::set_user_fs_base(fs_base);
            }
            // Publish for the own-stack kernel_switch resume path: a
            // preempted/parked task resumes WITHOUT re-running this poll, so
            // `poll_to_yield` must reload FS_BASE from the per-task slot or the
            // task runs on another thread's TLS (SMP multithread TLS corruption).
            #[cfg(target_arch = "x86_64")]
            narf_scheduler::stackful::set_current_user_fs_base(fs_base);
        }

        // Interrupts off across the iretq. The trap handler
        // re-enables them on its swapgs path; the hook + longjmp
        // path keeps IF=0 (per the kernel-test build's "no LAPIC
        // timer → leaving IF=1 turns the next halt_until_irq into a
        // wedge" rationale captured in commit 401b073).
        // SAFETY: cli has no memory effect.
        unsafe {
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }

        // Mark the start of this user run-slice for CPU-time accounting
        // (getrusage / times). Captured here (before setjmp, only read
        // after the trap-return below — never mutated in between, so it is
        // longjmp-safe) so the delta covers entry→trap, i.e. the time the
        // task actually executed in user mode. See `account_user_cpu_ns`.
        let slice_start_ns = narf_scheduler::narf_time::monotonic_ns();

        // ── Per-task-own-stack model (the new path) ──────────────────
        // The task runs on its OWN kernel stack with TSS.rsp0 / SYSCALL gs:[8]
        // pointed at it (set by `poll_to_yield`). Enter user mode at the TOP of
        // that stack — `*_at_top` resets RSP so the kernel stack is EMPTY while
        // the user runs — and let the task live via traps (`try_preempt_user`)
        // + the scheduler park/exit primitives. This diverges; the poll is NOT
        // re-entered (the trap continuation is saved in the KernelTask ctx).
        if narf_scheduler::stackful::user_own_stack_enabled() {
            // Publish the FPU area so the scheduler's preempt/park can
            // FXSAVE/FXRSTOR it across a kernel_switch, then restore it now.
            narf_scheduler::stackful::set_current_user_fpu(&*this.fpu as *const FpuArea as *mut u8);
            // SAFETY: live FpuArea (≥FPU_AREA_SIZE, 64-aligned); CR4.OSFXSR/OSXSAVE set.
            unsafe {
                narf_arch::x86_64::xsave::fpu_restore(&*this.fpu as *const FpuArea as *const u8);
            }
            let top = narf_scheduler::stackful::current_stackful_stack_top();
            let _ = slice_start_ns; // CPU accounting on the own-stack path TODO
            match this.state {
                TaskState::Initial => {
                    this.state = TaskState::Running;
                    let entry = this.process.entry.0.as_u64();
                    let rsp = this.process.stack_top.as_u64();
                    if let Some(arg) = this.process.entry_arg {
                        // SAFETY: AS activated + entry/rsp mapped by construction;
                        // never returns (iretq into CPL=3 on this task's stack top).
                        unsafe {
                            narf_scheduler::enter_user_mode_with_arg_at_top(entry, rsp, arg, top)
                        }
                    } else {
                        // SAFETY: AS activated + entry/rsp mapped by construction;
                        // never returns (iretq into CPL=3 on this task's stack top).
                        unsafe { narf_scheduler::enter_user_mode_at_top(entry, rsp, top) }
                    }
                }
                TaskState::Running => {
                    narf_lib::perf::ctx_switch();
                    // SAFETY: `ctx.state` holds a prior trap-from-user snapshot
                    // (fork child / re-image); resume it on the empty stack top.
                    unsafe {
                        narf_scheduler::enter_user_mode_resume_at_top(
                            this.task.uctx.state.get(),
                            top,
                        )
                    }
                }
                TaskState::Exited => unreachable!("guarded above"),
            }
            // unreachable — the `*_at_top` calls diverge.
        }

        // ── Legacy longjmp model (the old path) ──────────────────────
        // setjmp. On the initial call returns 0; the hooks longjmp
        // back here with a non-zero EXIT_REASON_*.
        // SAFETY: jmp is a valid, properly-aligned JmpBuf for the
        // duration of this `poll` body (Pin guarantees stable
        // address; UnsafeCell gives interior mutability without
        // creating an aliased &mut while the longjmp executes).
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { narf_scheduler::setjmp(this.jmp.get()) };

        if saved == 0 {
            // Restore this task's x87/SSE register file before re-entering
            // user mode. Without this a task resuming after preemption
            // (especially on a different CPU under migration) would run
            // with whatever XMM/x87 the previously-polled user task left
            // behind — corrupting an in-flight `memcpy`/`memset`. The
            // kernel is `+soft-float` so nothing has touched the FPU since
            // the matching `FXSAVE` on the last trap-return.
            // SAFETY: `fpu` is a live FpuArea (≥FPU_AREA_SIZE, 64-aligned; Pin
            // keeps the future's address stable); CR4.OSFXSR/OSXSAVE is set on
            // every CPU; the buffer lives in kernel memory mapped in the
            // active (user) AS's kernel half.
            unsafe {
                narf_arch::x86_64::xsave::fpu_restore(&*this.fpu as *const FpuArea as *const u8);
            }
            match this.state {
                TaskState::Initial => {
                    this.state = TaskState::Running;
                    let entry = this.process.entry.0.as_u64();
                    let rsp = this.process.stack_top.as_u64();
                    // SAFETY: the AS is activated and the user
                    // mappings cover entry + rsp by construction
                    // (load_user_process_with mapped them). Never
                    // returns — control reaches CPL=3. When the
                    // process carries an entry_arg (clone(2) for
                    // pthread start), deliver it as the first
                    // SysV integer arg (RDI).
                    if let Some(arg) = this.process.entry_arg {
                        // SAFETY: the AS is activated and the user
                        // mappings cover `entry` + `rsp` by construction
                        // (`load_user_process_with` mapped them); `arg`
                        // is the clone(2) start argument delivered in
                        // RDI. Never returns — control reaches CPL=3.
                        // SAFETY: Valid memory or trusted environment
                        unsafe { narf_scheduler::enter_user_mode_with_arg(entry, rsp, arg) }
                    } else {
                        // SAFETY: as above — AS activated, `entry`/`rsp`
                        // mapped by construction; never returns (iretq
                        // into CPL=3).
                        // SAFETY: Valid memory or trusted environment
                        unsafe { narf_scheduler::enter_user_mode(entry, rsp) }
                    }
                }
                TaskState::Running => {
                    // SAFETY: a prior poll's trap path populated
                    // `ctx.state` via `TrapContext::save_user_state`;
                    // the AS is re-activated and kernel state (TSS rsp0,
                    // GS) is still correct from first entry. Never
                    // returns — iretq resumes the saved user frame.
                    narf_lib::perf::ctx_switch();
                    // SAFETY: Valid memory or trusted environment
                    unsafe { narf_scheduler::enter_user_mode_resume(this.task.uctx.state.get()) }
                }
                TaskState::Exited => unreachable!("guarded above"),
            }
        }

        // The trap returned control here: this user run-slice just ended.
        // Charge the elapsed user-mode time to the running task so
        // getrusage(RUSAGE_SELF) / times() report real consumed CPU time
        // rather than wall-clock uptime. `current_task_id()` is still this
        // task (install_current set it at the top of poll, before setjmp).
        {
            let now = narf_scheduler::narf_time::monotonic_ns();
            crate::handlers::account_user_cpu_ns(now.saturating_sub(slice_start_ns));
        }

        // Save this task's x87/SSE register file. The trap left the
        // user's live XMM/x87 in the hardware registers (the kernel is
        // `+soft-float` and never touches them), and the executor is
        // about to poll other user tasks that WILL clobber them. FXSAVE
        // snapshots them so the next resume's FXRSTOR restores exactly
        // this task's FPU state — the crux of preserving an in-flight
        // user `memcpy` across preemption + migration.
        // SAFETY: `fpu` is a live FpuArea (≥FPU_AREA_SIZE, 64-aligned); the
        // user AS is still active here (CR3 restore is below) and `fpu`
        // is in its kernel half; CR4.OSFXSR/OSXSAVE is set.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            narf_arch::x86_64::xsave::fpu_save(&mut *this.fpu as *mut FpuArea as *mut u8);
        }

        // Longjmp path: a hook fired, control is back on the
        // kernel-side stack. Restore the kernel's saved CR3 + zero
        // KERNEL_GS_BASE + keep IF=0 (cli, NOT sti — see commit
        // 401b073 for the rationale: the kernel-test build never
        // enables the LAPIC timer, so a halt_until_irq with IF=1
        // wedges).
        let cr3 = this.saved_cr3.get().expect("saved_cr3 set on entry");
        // SAFETY: CR3 came from a `mov cr3` snapshot taken on the
        // same kernel root; restoring it is safe.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }

        // Tear down the published per-task pointers before we
        // return to the executor; an unrelated trap on the next
        // round must not see this future's slots.
        clear_current();
        jmp_slot().store(core::ptr::null_mut(), Ordering::Release);

        let reason = saved as u32;
        if reason == EXIT_REASON_EXITED {
            // Flip the refcounted task to ZOMBIE. It stays resolvable
            // (carrying its exit code) until the parent reaps it —
            // `crate::task::release_task` drops the registry ref there.
            // The future's own `Arc<Task>` keeps the `UserTaskCtx`
            // alive until the executor drops this slot, so no wake can
            // dangle regardless of ordering.
            crate::task::mark_zombie(crate::handlers::current_task_id());
            // Fan out to per-pid observers (FB connections, fd
            // tables, future ipc rings) before flipping state so
            // any subsystem that wants to inspect the live process
            // sees it pre-teardown.
            notify_task_exited(this.process.pid.raw(), crate::handlers::current_task_id());
            this.state = TaskState::Exited;
            core::task::Poll::Ready(())
        } else if reason == EXIT_REASON_EXECVE {
            // sys_execve handed us a pre-built ExecRequest: swap
            // the future's UserProcess to point at the new image's
            // AS / entry / stack, transition back to Initial so
            // the next iteration of the polling routine enters
            // user mode at the new entry, and immediately re-poll.
            // POSIX execve(2) preserves the task's PID, fd table,
            // brk top, and signal handler table — those live in
            // crate-side tables keyed by pid, untouched here.
            let req_ptr = this
                .task
                .uctx
                .pending_exec
                .swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !req_ptr.is_null() {
                // SAFETY: the syscall handler allocated this with
                // `Box::into_raw(Box::new(ExecRequest{..}))` and
                // published the pointer into `pending_exec` before
                // longjmp'ing here; we're the sole consumer.
                // SAFETY: Valid memory or trusted environment
                let req = unsafe { alloc::boxed::Box::from_raw(req_ptr) };
                this.process.address_space = req.new_as;
                this.process.entry = crate::EntryPoint(narf_memory::VirtAddr::new(req.entry));
                this.process.stack_top = narf_memory::VirtAddr::new(req.stack_top);
                this.process.fs_base = req.fs_base;
                this.state = TaskState::Initial;
            }
            // Repoll — the next iteration runs the Initial-state
            // path which calls activate() on the new AS and
            // enter_user_mode at the new entry.
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        } else {
            // EXIT_REASON_YIELDED or any unknown reason — repoll.
            // Wake immediately so the executor visits us again on
            // the next round.
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    }
}

// ── aarch64 polling future ─────────────────────────────────────────

/// Aarch64 sibling of the x86_64 UserTaskFuture. Same lifecycle:
/// install_current → activate user TTBR0 → setjmp → eret to EL0 →
/// trap-back longjmps into the polling routine via CURRENT_JMP.
///
/// `activate()` on aarch64 swaps TTBR0_EL1 to the AS's root; the
/// kernel keeps reading/writing through TTBR1's high-half mapping
/// (every kernel-side phys access goes through
/// `PhysAddr::kernel_ptr` / `kernel_mut_ptr`). If `activate()`
/// returns Err (e.g. unset root, unsupported arch fallback), we
/// degrade gracefully — fan out exit observers + return
/// `Poll::Ready(())` — so the future never crashes the executor.
#[cfg(target_arch = "aarch64")]
pub struct UserTaskFuture {
    process: crate::UserProcess,
    /// Refcounted task object — see the x86_64 sibling's field doc.
    task: alloc::sync::Arc<crate::task::Task>,
    jmp: UnsafeCell<JmpBuf>,
    state: TaskState,
    /// Snapshot of the kernel's TTBR0_EL1 captured on the first
    /// poll so we can restore it on the trap-back path. `None`
    /// until the first poll runs.
    saved_ttbr0: core::cell::Cell<Option<u64>>,
}

#[cfg(target_arch = "aarch64")]
impl core::fmt::Debug for UserTaskFuture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserTaskFuture")
            .field("pid", &self.process.pid)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(target_arch = "aarch64")]
// SAFETY: identical reasoning to the x86_64 impl — single-CPU
// cooperative executor, the future never escapes the executor's
// Pin<Box<...>>, the UnsafeCell-wrapped JmpBuf is only written by
// poll between install_current and setjmp.
unsafe impl Send for UserTaskFuture {}

#[cfg(target_arch = "aarch64")]
impl UserTaskFuture {
    /// Construct a fresh polling future for `process`, bound to its
    /// pre-registered refcounted `task`. Hand to
    /// `narf_scheduler::spawn_user` under the same reserved `TaskId`.
    pub fn new(process: crate::UserProcess, task: alloc::sync::Arc<crate::task::Task>) -> Self {
        Self {
            process,
            task,
            jmp: UnsafeCell::new(JmpBuf::default()),
            state: TaskState::Initial,
            saved_ttbr0: core::cell::Cell::new(None),
        }
    }

    /// Construct a polling future seeded with a pre-populated
    /// `UserState`. First poll calls `enter_user_mode_resume`
    /// against the saved state instead of `enter_user_mode(pc,
    /// sp)`. Used by `sys_fork` so the child wakes at the
    /// parent's post-`svc #0` PC with x0=0 / x1=0 (POSIX fork
    /// return).
    pub fn resume_with(
        process: crate::UserProcess,
        task: alloc::sync::Arc<crate::task::Task>,
        state: UserState,
    ) -> Self {
        // SAFETY: the task was just registered and never enqueued —
        // no other CPU can touch its `uctx` yet.
        unsafe {
            *task.uctx.state.get() = state;
        }
        Self {
            process,
            task,
            jmp: UnsafeCell::new(JmpBuf::default()),
            state: TaskState::Running,
            saved_ttbr0: core::cell::Cell::new(None),
        }
    }

    pub fn process(&self) -> &crate::UserProcess {
        &self.process
    }

    pub fn task_state(&self) -> TaskState {
        self.state
    }
}

#[cfg(target_arch = "aarch64")]
impl core::future::Future for UserTaskFuture {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        // SAFETY: don't move out of Pin; only project to fields
        // whose address stability we own.
        // SAFETY: Valid memory or trusted environment
        let this = unsafe { self.get_unchecked_mut() };

        if this.state == TaskState::Exited {
            return core::task::Poll::Ready(());
        }

        // Job-control stop: keep a stopped task parked until SIGCONT
        // (or SIGKILL) — see the x86_64 sibling body for rationale.
        {
            let tp = crate::handlers::current_task_id();
            if crate::handlers::is_task_stopped(tp)
                && (crate::handlers::signal_pending_bits(tp) & (1 << 9)) == 0
            {
                crate::handlers::register_signal_waker(tp, cx.waker().clone());
                return core::task::Poll::Pending;
            }
        }

        // sys_sleep park-via-deadline + throttle (mirrors x86_64 —
        // see the sibling poll body for the rationale).
        let deadline = this.task.uctx.sleep_deadline_ns.load(Ordering::Acquire);
        if deadline != 0 {
            let now = narf_scheduler::narf_time::monotonic_ns();
            // Break ANY park (finite deadlines included — Linux
            // interruptible-sleep semantics; see the x86_64 sibling) on an
            // async deliverable pending signal. A sigwait park (non-zero
            // `sigwait_set`, finite deadline or not) additionally breaks on
            // a pending signal in its waited set (mask ignored) so the
            // rewound rt_sigtimedwait re-executes and consumes it.
            let tid = crate::handlers::current_task_id();
            let sw = this.task.uctx.sigwait_set.load(Ordering::Acquire);
            let signal_pending = crate::handlers::is_signal_pending(tid)
                || (sw != 0 && crate::handlers::sigwait_should_wake(tid, sw));
            if now < deadline && !signal_pending {
                const PARK_CHUNK_NS: u64 = 1_000_000;
                let chunk_end = now.saturating_add(PARK_CHUNK_NS).min(deadline);
                while narf_scheduler::narf_time::monotonic_ns() < chunk_end {
                    crate::handlers::sleep_pumps::run();
                    core::hint::spin_loop();
                }
                cx.waker().wake_by_ref();
                return core::task::Poll::Pending;
            }
            this.task.uctx.sleep_deadline_ns.store(0, Ordering::Release);
            this.task.uctx.sigwait_set.store(0, Ordering::Release);
        }

        // sys_wait4 cooperative parking (mirrors x86_64 poll body).
        if this.task.uctx.wait_child_pending.load(Ordering::Acquire) {
            let want_pid = this.task.uctx.wait_child_want_pid.load(Ordering::Acquire);
            let wait_options = this.task.uctx.wait_child_options.load(Ordering::Acquire);
            let status_ptr = this.task.uctx.wait_child_status_ptr.load(Ordering::Acquire);
            // Use the scheduler TaskId (set by CURRENT_TASK before this poll)
            // as the key to look up PENDING_EXITS. `sys_fork` stores the
            // parent's TaskId (`current_task_id()`) into PARENT_OF and
            // PENDING_EXITS, so the lookup key must also be the TaskId.
            let task_pid = crate::handlers::current_task_id();
            let mut child_status = 0i32;
            let reaped = call_wait_child_check(task_pid, want_pid, wait_options, &mut child_status);
            if reaped > 0 {
                let is_waitid = this.task.uctx.wait_child_is_waitid.load(Ordering::Acquire);
                let rax =
                    crate::handlers::finish_wait_child(status_ptr, is_waitid, reaped, child_status);
                // SAFETY: `state.get()` is the `*mut UserState`
                // (== `*mut narf_scheduler::UserState`) backing this
                // future's saved frame; we own it (Pin-stable) and no
                // other handle aliases it here.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    #[cfg(target_arch = "aarch64")]
                    {
                        // On aarch64 x0 is the return register.
                        let us = &mut *this.task.uctx.state.get();
                        us.x[0] = rax;
                    }
                }
                this.task
                    .uctx
                    .wait_child_pending
                    .store(false, Ordering::Release);
                this.task
                    .uctx
                    .wait_child_is_waitid
                    .store(false, Ordering::Release);
            } else {
                register_wait_child_waker(task_pid, cx.waker().clone());
                let mut child_status2 = 0i32;
                let reaped2 =
                    call_wait_child_check(task_pid, want_pid, wait_options, &mut child_status2);
                if reaped2 > 0 {
                    drop_wait_child_waker(task_pid);
                    let is_waitid = this.task.uctx.wait_child_is_waitid.load(Ordering::Acquire);
                    let rax = crate::handlers::finish_wait_child(
                        status_ptr,
                        is_waitid,
                        reaped2,
                        child_status2,
                    );
                    // SAFETY: `state.get()` is the `*mut UserState`
                    // backing this future's saved frame; we own it
                    // (Pin-stable) and no other handle aliases it here.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        #[cfg(target_arch = "aarch64")]
                        {
                            let us = &mut *this.task.uctx.state.get();
                            us.x[0] = rax;
                        }
                    }
                    this.task
                        .uctx
                        .wait_child_pending
                        .store(false, Ordering::Release);
                    this.task
                        .uctx
                        .wait_child_is_waitid
                        .store(false, Ordering::Release);
                } else {
                    // wait4 is signal-interruptible (Linux): register a SIGNAL
                    // waker so an async signal (e.g. ITIMER_REAL SIGALRM fired
                    // from the timer tick while parked) wakes us even with no
                    // child exit; if a deliverable signal is already pending,
                    // abandon the wait with EINTR and fall through to deliver.
                    // See the x86_64 poll for the full rationale.
                    crate::handlers::register_signal_waker(task_pid, cx.waker().clone());
                    if crate::handlers::has_interrupting_signal(task_pid) {
                        drop_wait_child_waker(task_pid);
                        // SAFETY: `state.get()` is the `*mut UserState` backing
                        // this future's saved frame; we own it (Pin-stable) and
                        // no other handle aliases it here.
                        unsafe {
                            #[cfg(target_arch = "aarch64")]
                            {
                                let us = &mut *this.task.uctx.state.get();
                                us.x[0] = (-4i64) as u64; // -EINTR
                            }
                        }
                        this.task
                            .uctx
                            .wait_child_pending
                            .store(false, Ordering::Release);
                        this.task
                            .uctx
                            .wait_child_is_waitid
                            .store(false, Ordering::Release);
                        // Fall through to re-enter user mode (delivers SIGALRM).
                    } else {
                        return core::task::Poll::Pending;
                    }
                }
            }
        }

        // (Task registration happens at spawn time — see the x86_64
        // sibling poll for the rationale.)

        // Snapshot kernel TTBR0_EL1 once. Subsequent polls land
        // back here via the trap path; we restore on the way out.
        if this.saved_ttbr0.get().is_none() {
            let ttbr0: u64;
            // SAFETY: reading TTBR0_EL1 has no side effects.
            unsafe {
                core::arch::asm!("mrs {v}, TTBR0_EL1", v = out(reg) ttbr0,
                    options(nostack, preserves_flags));
            }
            this.saved_ttbr0.set(Some(ttbr0));
        }

        // Activate the user AS. Until the kernel heap migrates
        // off TTBR0, this returns NotImplemented; degrade by
        // resolving Ready immediately (no EL0 entry possible).
        if this.process.address_space.activate().is_err() {
            // No state change — the task essentially never ran
            // user code. Fan out the exit observers and resolve.
            crate::task::mark_zombie(crate::handlers::current_task_id());
            notify_task_exited(this.process.pid.raw(), crate::handlers::current_task_id());
            this.state = TaskState::Exited;
            return core::task::Poll::Ready(());
        }

        // Publish per-task pointers the trap path consults.
        install_current(&this.task.uctx as *const UserTaskCtx as *mut UserTaskCtx);
        jmp_slot().store(this.jmp.get(), Ordering::Release);

        // Program the per-task TLS thread pointer if the binary
        // staged a TLS block. AArch64 stores it in TPIDR_EL0;
        // pairing the write with the AS activation keeps the
        // "outgoing user task's MSRs" mental model intact.
        if let Some(tls_base) = this.process.fs_base {
            // SAFETY: writing TPIDR_EL0 at EL1 is unconditional
            // and has no side effects on EL1 state.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_scheduler::set_user_tls_base(tls_base);
            }
        }

        // Mask all DAIF (IRQ/FIQ/SError/Debug) across the eret —
        // the EL0 entry's SPSR carries the user-mode DAIF; the
        // trap-back path keeps DAIF masked through the longjmp.
        // SAFETY: msr DAIFSet has no memory effect.
        unsafe {
            core::arch::asm!(
                "msr DAIFSet, #0xF",
                options(nomem, nostack, preserves_flags)
            );
        }

        // setjmp. On the initial call returns 0; the hooks
        // longjmp back here with a non-zero EXIT_REASON_*.
        // SAFETY: jmp is a valid JmpBuf for the duration of this
        // poll body; Pin pins the address.
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { narf_scheduler::setjmp(this.jmp.get()) };

        if saved == 0 {
            match this.state {
                TaskState::Initial => {
                    this.state = TaskState::Running;
                    let pc = this.process.entry.0.as_u64();
                    let sp = this.process.stack_top.as_u64();
                    // SAFETY: AS is activated; the user mappings
                    // for pc + sp live in the now-active TTBR0.
                    // SAFETY: Valid memory or trusted environment
                    unsafe { narf_scheduler::enter_user_mode(pc, sp) }
                }
                TaskState::Running => {
                    // SAFETY: a prior poll's trap path populated
                    // ctx.state via TrapContext::save_user_state.
                    narf_lib::perf::ctx_switch();
                    // SAFETY: Valid memory or trusted environment
                    unsafe { narf_scheduler::enter_user_mode_resume(this.task.uctx.state.get()) }
                }
                TaskState::Exited => unreachable!("guarded above"),
            }
        }

        // Longjmp path: a hook fired, control is back on the
        // kernel-side stack. Restore the kernel's saved TTBR0
        // and keep DAIF masked.
        let ttbr0 = this.saved_ttbr0.get().expect("saved_ttbr0 set on entry");
        // SAFETY: ttbr0 came from a prior MSR snapshot of the
        // active kernel root; restoring is symmetric.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "msr TTBR0_EL1, {v}",
                "isb",
                v = in(reg) ttbr0,
                options(nostack, preserves_flags),
            );
            // Local TLB invalidate (broadcast not needed here —
            // the ready queue serialises this task).
            core::arch::asm!(
                "tlbi vmalle1",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags),
            );
            core::arch::asm!(
                "msr DAIFSet, #0xF",
                options(nomem, nostack, preserves_flags)
            );
        }

        clear_current();
        jmp_slot().store(core::ptr::null_mut(), Ordering::Release);

        let reason = saved as u32;
        if reason == EXIT_REASON_EXITED {
            crate::task::mark_zombie(crate::handlers::current_task_id());
            notify_task_exited(this.process.pid.raw(), crate::handlers::current_task_id());
            this.state = TaskState::Exited;
            core::task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn user_task_yield_hook(_uctx: *mut UserTaskCtx) -> ! {
    let p = jmp_slot().load(Ordering::Acquire);
    if p.is_null() {
        narf_scheduler::halt_forever();
    }
    // SAFETY: same contract as the x86_64 sibling — the polling
    // routine guarantees CURRENT_JMP points at a live JmpBuf for
    // the duration of the user-mode round-trip.
    // SAFETY: Valid memory or trusted environment
    unsafe { narf_scheduler::longjmp(p as *const _, EXIT_REASON_YIELDED as u64) }
}

#[cfg(target_arch = "aarch64")]
unsafe fn user_task_exit_hook(_uctx: *mut UserTaskCtx) -> ! {
    let p = jmp_slot().load(Ordering::Acquire);
    if p.is_null() {
        narf_scheduler::halt_forever();
    }
    // SAFETY: same as above.
    unsafe { narf_scheduler::longjmp(p as *const _, EXIT_REASON_EXITED as u64) }
}

#[cfg(target_arch = "aarch64")]
pub fn install_user_task_hooks() {
    install_yield_hook(user_task_yield_hook);
    install_exit_hook(user_task_exit_hook);
    narf_scheduler::stackful::set_user_perf_switch_hook(crate::perf_event::on_task_switch);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[derive(Debug)]
pub struct UserTaskFuture {
    _process: crate::UserProcess,
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl UserTaskFuture {
    pub fn new(process: crate::UserProcess, _task: alloc::sync::Arc<crate::task::Task>) -> Self {
        Self { _process: process }
    }

    pub fn resume_with(
        process: crate::UserProcess,
        _task: alloc::sync::Arc<crate::task::Task>,
        _state: UserState,
    ) -> Self {
        Self { _process: process }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl core::future::Future for UserTaskFuture {
    type Output = ();
    fn poll(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        core::task::Poll::Ready(())
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn install_user_task_hooks() {}

// ── User-task spawn entry points ────────────────────────────────────
//
// ALL user-task spawns (boot init, fork, clone) go through these helpers so
// the refcounted `Task` is registered under its reserved `TaskId` BEFORE the
// slot is enqueued — the task must be resolvable via `crate::task::task_get`
// from its very first instruction.

/// A registered user task which has not yet been made runnable.
///
/// Fork-like syscalls must install all of the child's inherited kernel state
/// (fd table, namespaces, signal state, cgroup membership, and so on) before
/// its first instruction can run.  In particular, `posix_spawn` commonly
/// performs an immediate `execveat(AT_EMPTY_PATH)` through an inherited fd;
/// enqueuing before `fd::fork` creates an SMP race where that lookup observes
/// no child table and spuriously returns `ENOENT`.
pub struct PendingUserProcess {
    id: narf_scheduler::TaskId,
    future: UserTaskFuture,
    spec: narf_scheduler::TaskSpec,
    addr_space: alloc::sync::Arc<narf_memory::AddressSpace>,
}

impl core::fmt::Debug for PendingUserProcess {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingUserProcess")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl PendingUserProcess {
    /// The reserved task id, usable as the key for inheritance state before
    /// [`Self::spawn`] publishes the task to the scheduler.
    pub const fn task_id(&self) -> narf_scheduler::TaskId {
        self.id
    }

    /// Publish this fully initialized task to the scheduler.
    pub fn spawn(self) -> narf_scheduler::TaskId {
        narf_scheduler::spawn_user(self.id, self.future, self.spec, self.addr_space)
    }
}

fn prepare_user_process(
    process: crate::UserProcess,
    future: impl FnOnce(crate::UserProcess, alloc::sync::Arc<crate::task::Task>) -> UserTaskFuture,
    spec: narf_scheduler::TaskSpec,
) -> PendingUserProcess {
    let id = narf_scheduler::alloc_task_id();
    let addr_space = process.address_space.clone();
    let task = crate::task::Task::new_registered(id.raw(), process.pid.raw());
    PendingUserProcess {
        id,
        future: future(process, task),
        spec,
        addr_space,
    }
}

/// Register a fresh user task without making it runnable.  Callers that need
/// no child-state setup should use [`spawn_user_process`] instead.
pub fn prepare_user_process_initial(
    process: crate::UserProcess,
    spec: narf_scheduler::TaskSpec,
) -> PendingUserProcess {
    prepare_user_process(process, UserTaskFuture::new, spec)
}

/// Register a fork/clone child with its saved user state, but do not make it
/// runnable until the caller has installed all inherited kernel state.
pub fn prepare_user_process_resume(
    process: crate::UserProcess,
    state: UserState,
    spec: narf_scheduler::TaskSpec,
) -> PendingUserProcess {
    prepare_user_process(
        process,
        move |process, task| UserTaskFuture::resume_with(process, task, state),
        spec,
    )
}

/// Reserve a `TaskId`, register the refcounted `Task`, and enqueue a
/// fresh polling future for `process` under that id.
pub fn spawn_user_process(
    process: crate::UserProcess,
    spec: narf_scheduler::TaskSpec,
) -> narf_scheduler::TaskId {
    prepare_user_process_initial(process, spec).spawn()
}

/// Same as [`spawn_user_process`] but seeds the child with a saved
/// `UserState` snapshot (fork/clone resume-into-child).
pub fn spawn_user_process_resume(
    process: crate::UserProcess,
    state: UserState,
    spec: narf_scheduler::TaskSpec,
) -> narf_scheduler::TaskId {
    prepare_user_process_resume(process, state, spec).spawn()
}
