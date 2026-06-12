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
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU64, Ordering};

use alloc::collections::BTreeMap;
use narf_lib::sync::IrqSafeSpinLock;

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

    /// Distinguishes `waitid(2)` from `wait4(2)` for the blocking
    /// path: when set, the reap writes a `siginfo_t` to
    /// `wait_child_status_ptr` and the syscall returns 0 rather than
    /// writing a wstatus `int` and returning the reaped pid.
    pub wait_child_is_waitid: AtomicBool,
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
            pending_exec: AtomicPtr::new(core::ptr::null_mut()),
            pending_fs_base: AtomicU64::new(u64::MAX),
            wait_child_pending: AtomicBool::new(false),
            wait_child_want_pid: AtomicI64::new(0),
            wait_child_status_ptr: AtomicU64::new(0),
            wait_child_is_waitid: AtomicBool::new(false),
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

/// Single-task slot the polling routine populates before transitioning
/// to user mode. Trap handlers consult this to find the calling
/// task's `UserTaskCtx`. SMP will replace this with a per-CPU
/// pointer; until then the cooperative single-CPU executor
/// guarantees only one task is ever in flight.
static CURRENT: AtomicPtr<UserTaskCtx> = AtomicPtr::new(core::ptr::null_mut());

pub fn install_current(ctx: *mut UserTaskCtx) {
    CURRENT.store(ctx, Ordering::Release);
}

pub fn clear_current() {
    CURRENT.store(core::ptr::null_mut(), Ordering::Release);
}

pub fn current_user_task() -> Option<*mut UserTaskCtx> {
    // The in-flight polling routine publishes its ctx in `CURRENT`
    // right before entering user mode and clears it on the way back
    // out, so it reflects exactly the task whose trap we're handling.
    // We deliberately do NOT fall back to the task-id registry here:
    // its entries point at the poller's stack-pinned `UserTaskCtx`,
    // which is only live while that task is the in-flight one — a
    // lookup by id can hand back a pointer to a future that has since
    // unwound (notably in the in-kernel test harness, where `CURRENT`
    // is never set). `wake_signal` consults the registry directly when
    // it genuinely needs to poke a parked task by id.
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct SendPtr<T>(pub *mut T);
// SAFETY: `SendPtr` is a raw `*mut UserTaskCtx` newtype stored in the
// `USER_TASK_CTXS` registry. The pointer targets a poller-pinned
// `UserTaskCtx` that is only dereferenced on the single cooperative
// CPU while that task is in flight; the wrapper carries no ownership,
// so transferring it across the (single-CPU) executor is sound.
unsafe impl<T> Send for SendPtr<T> {}
// SAFETY: as above — the wrapper only hands back the bare pointer; any
// dereference happens on the single cooperative CPU, so shared `&`
// access across the registry never races a live `&mut`.
unsafe impl<T> Sync for SendPtr<T> {}

static USER_TASK_CTXS: IrqSafeSpinLock<Option<BTreeMap<u64, SendPtr<UserTaskCtx>>>> =
    IrqSafeSpinLock::new(None);

pub fn user_task_ctx_init() {
    *USER_TASK_CTXS.lock() = Some(BTreeMap::new());
}

pub fn register_user_task_ctx(task_id: u64, ctx: *mut UserTaskCtx) {
    let mut g = USER_TASK_CTXS.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task_id, SendPtr(ctx));
    }
}

pub fn lookup_user_task_ctx(task_id: u64) -> Option<*mut UserTaskCtx> {
    let g = USER_TASK_CTXS.lock();
    g.as_ref()?.get(&task_id).map(|p| p.0)
}

pub fn unregister_user_task_ctx(task_id: u64) {
    let mut g = USER_TASK_CTXS.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&task_id);
    }
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

// ── Process-exit observers ────────────────────────────────────────
//
// Subsystems that hold per-process resources (FB connections, fd
// tables, ipc rings) register an observer here. When a polled
// UserTaskFuture sees EXIT_REASON_EXITED, every registered observer
// is invoked with the dying process's pid before the future resolves
// to Ready. Observers run in plain kernel context (not in the trap
// path) and may take spinlocks / call into other subsystems.
//
// Observers are append-only — there's no unregister. The intent is
// boot-time wiring, not runtime hot-swap.

pub type ExitObserver = fn(pid: u64, tid: u64);

static EXIT_OBSERVERS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<ExitObserver>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Register a callback to fire when a polled user task transitions
/// to Exited. Invoked exactly once per task with `(pid, tid)`:
///   * `pid` — the user-visible process group id. For
///     `CLONE_THREAD` children this equals the parent's pid, so
///     thread-aware bookkeeping (clear_child_tid, futex wait
///     queues) must key on `tid` instead.
///   * `tid` — the scheduler's `TaskId.raw()` for the exited
///     task. Always distinct from sibling threads.
pub fn register_exit_observer(o: ExitObserver) {
    EXIT_OBSERVERS.lock().push(o);
}

/// Fan out the exit notification. Called by `UserTaskFuture::poll`
/// when it sees `EXIT_REASON_EXITED`. Also exposed for test
/// harnesses that want to drive the observer fan-out without
/// running a full polling future.
pub fn notify_task_exited(pid: u64, tid: u64) {
    let observers = EXIT_OBSERVERS.lock().clone();
    for o in observers.iter() {
        o(pid, tid);
    }
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_clear_exit_observers() {
    EXIT_OBSERVERS.lock().clear();
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_clear_hooks() {
    YIELD_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    EXIT_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    clear_current();
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
pub type WaitChildCheckFn = fn(parent_id: u64, want_pid: i64, out_status: *mut i32) -> i64;

static WAIT_CHILD_CHECK_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the wait4 reap-check callback.  Called once at boot by
/// `handlers::wait_init`.
pub fn register_wait_child_check(f: WaitChildCheckFn) {
    WAIT_CHILD_CHECK_FN.store(f as *mut (), Ordering::Release);
}

/// Invoke the registered check callback.  Returns 0 if no callback
/// is installed (test/fallback context without real wait4 tables).
pub fn call_wait_child_check(parent_id: u64, want_pid: i64, out_status: *mut i32) -> i64 {
    let p = WAIT_CHILD_CHECK_FN.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    // SAFETY: p was stored by `register_wait_child_check` with a valid
    // WaitChildCheckFn; the static lifetime outlives any call.
    // SAFETY: Valid memory or trusted environment
    let f: WaitChildCheckFn = unsafe { core::mem::transmute(p) };
    f(parent_id, want_pid, out_status)
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
/// unrelated trap.
static CURRENT_JMP: AtomicPtr<JmpBuf> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(target_arch = "x86_64")]
unsafe fn user_task_yield_hook(_uctx: *mut UserTaskCtx) -> ! {
    // The syscall handler already populated `*uctx.exit_reason` and
    // `*uctx.state` before tail-calling us. Our job is just to
    // longjmp back to the polling routine; the polling routine
    // reads `exit_reason` after setjmp returns non-zero.
    let p = CURRENT_JMP.load(Ordering::Acquire);
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
    let p = CURRENT_JMP.load(Ordering::Acquire);
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
    let p = CURRENT_JMP.load(Ordering::Acquire);
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
    ctx: UserTaskCtx,
    jmp: UnsafeCell<JmpBuf>,
    state: TaskState,
    /// Snapshot of the kernel's CR3 captured on the first poll so
    /// we can restore it on the return path. `None` until the first
    /// poll runs.
    saved_cr3: core::cell::Cell<Option<u64>>,
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
    /// Construct a fresh polling future for `process`. The future
    /// is not yet on any ready queue — hand it to
    /// `narf_scheduler::spawn_user` to schedule it.
    pub fn new(process: crate::UserProcess) -> Self {
        Self {
            process,
            ctx: UserTaskCtx::new(),
            jmp: UnsafeCell::new(JmpBuf::default()),
            state: TaskState::Initial,
            saved_cr3: core::cell::Cell::new(None),
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
    pub fn resume_with(process: crate::UserProcess, state: UserState) -> Self {
        let ctx = UserTaskCtx::new();
        // SAFETY: we just constructed `ctx` and own the only handle
        // to it; nobody else can race the cell write.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            *ctx.state.get() = state;
        }
        Self {
            process,
            ctx,
            jmp: UnsafeCell::new(JmpBuf::default()),
            // Skip `Initial` so the first poll takes the
            // `enter_user_mode_resume` arm and walks the saved
            // state instead of the (entry, stack_top) pair.
            state: TaskState::Running,
            saved_cr3: core::cell::Cell::new(None),
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
        let deadline = this.ctx.sleep_deadline_ns.load(Ordering::Acquire);
        if deadline != 0 {
            let now = narf_scheduler::narf_time::monotonic_ns();
            // An asynchronously-raised signal (e.g. SIGALRM from an
            // interval timer that fired via a sleep-pump) must break an
            // *infinite* park — pause(2), or a blocking poll/epoll/futex
            // wait — so the task takes delivery on its next yield-point
            // syscall. We restrict this to `deadline == u64::MAX`: a
            // finite sleep(2) already wakes at its own deadline, and
            // un-parking it on a pending *ignored* signal (which no
            // syscall would then clear) would busy-spin. The pump still
            // runs at least once below before the signal becomes pending.
            let signal_pending = deadline == u64::MAX
                && crate::handlers::is_signal_pending(crate::handlers::current_task_id());
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
            // Deadline reached or a signal is pending — clear so the next
            // sys_sleep call doesn't see stale state, then fall through
            // to the normal resume path (which re-enters user mode; the
            // pending signal is delivered on the next yield syscall).
            this.ctx.sleep_deadline_ns.store(0, Ordering::Release);
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
        if this.ctx.wait_child_pending.load(Ordering::Acquire) {
            let want_pid = this.ctx.wait_child_want_pid.load(Ordering::Acquire);
            let status_ptr = this.ctx.wait_child_status_ptr.load(Ordering::Acquire);
            // Use the scheduler TaskId (set by CURRENT_TASK before this poll)
            // as the key to look up PENDING_EXITS. `sys_fork` stores the
            // parent's TaskId (`current_task_id()`) into PARENT_OF and
            // PENDING_EXITS, so the lookup key must also be the TaskId.
            let task_pid = crate::handlers::current_task_id();
            let mut child_status = 0i32;
            let reaped = call_wait_child_check(task_pid, want_pid, &mut child_status);
            if reaped > 0 {
                // Reap succeeded — write the wstatus (wait4) or
                // siginfo_t (waitid) to the user pointer and put the
                // syscall result (reaped pid for wait4, 0 for waitid)
                // into the saved RAX, then clear the pending flags.
                let is_waitid = this.ctx.wait_child_is_waitid.load(Ordering::Acquire);
                let rax =
                    crate::handlers::finish_wait_child(status_ptr, is_waitid, reaped, child_status);
                // SAFETY: `state.get()` is the `*mut UserState` (== `*mut
                // narf_scheduler::UserState`) backing this future's saved
                // frame; we own it (Pin-stable) and no other handle
                // aliases it here.
                unsafe {
                    #[cfg(target_arch = "x86_64")]
                    {
                        let us = &mut *this.ctx.state.get();
                        us.rax = rax;
                    }
                }
                this.ctx.wait_child_pending.store(false, Ordering::Release);
                this.ctx
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
                let reaped2 = call_wait_child_check(task_pid, want_pid, &mut child_status2);
                if reaped2 > 0 {
                    // Child exited in the window — remove the waker
                    // we just stored (no spurious self-wake needed),
                    // write the result, clear pending, fall through.
                    drop_wait_child_waker(task_pid);
                    let is_waitid = this.ctx.wait_child_is_waitid.load(Ordering::Acquire);
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
                            let us = &mut *this.ctx.state.get();
                            us.rax = rax;
                        }
                    }
                    this.ctx.wait_child_pending.store(false, Ordering::Release);
                    this.ctx
                        .wait_child_is_waitid
                        .store(false, Ordering::Release);
                    // Fall through to re-enter user mode.
                } else {
                    // Truly no child yet — park until `on_child_exit`
                    // wakes us.  Do NOT call wake_by_ref here.
                    return core::task::Poll::Pending;
                }
            }
        }

        let task_id = crate::handlers::current_task_id();
        register_user_task_ctx(task_id, &mut this.ctx as *mut _);

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
        install_current(&mut this.ctx as *mut _);
        CURRENT_JMP.store(this.jmp.get(), Ordering::Release);

        // Activate the user AS. `addr_space.activate()` does the
        // MOV CR3 on x86_64.
        let _ = this.process.address_space.activate();

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
        let override_fs = this.ctx.pending_fs_base.load(Ordering::Acquire);
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

        // setjmp. On the initial call returns 0; the hooks longjmp
        // back here with a non-zero EXIT_REASON_*.
        // SAFETY: jmp is a valid, properly-aligned JmpBuf for the
        // duration of this `poll` body (Pin guarantees stable
        // address; UnsafeCell gives interior mutability without
        // creating an aliased &mut while the longjmp executes).
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { narf_scheduler::setjmp(this.jmp.get()) };

        if saved == 0 {
            match this.state {
                TaskState::Initial => {
                    this.state = TaskState::Running;
                    let entry = this.process.entry.0.as_u64();
                    let rsp = this.process.stack_top.as_u64();
                    // Bring-up beacons (real-HW hang diagnosis):
                    //   slot 50 = about to iretq into a fresh user task
                    //   slot 52 = re-poll after trap-return (set below)
                    // If 50 lights but no 52 ever does, init is
                    // running in CPL=3 without trapping (infinite
                    // user-side loop, or stuck waiting for a kernel
                    // IRQ the scheduler hasn't delivered).
                    #[cfg(target_arch = "x86_64")]
                    narf_memory::beacon::paint(50, 0x00FF_60FF); // magenta: pre-iretq
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
                    // ctx.state via TrapContext::save_user_state.
                    // The AS is re-activated and the kernel state
                    // (TSS rsp0, GS) is still correct from the
                    // first entry.
                    #[cfg(target_arch = "x86_64")]
                    narf_memory::beacon::paint(51, 0x0060_FFFF); // cyan: pre-iretq-resume
                                                                 // SAFETY: `state.get()` is the `*mut UserState`
                                                                 // this future owns; a prior poll's trap path filled
                                                                 // it via `TrapContext::save_user_state`, so the
                                                                 // shared `&*` read is of an initialised, aligned
                                                                 // frame with no aliasing `&mut` live here.
                    #[cfg(target_arch = "x86_64")]
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        let _us = &*(this.ctx.state.get() as *const narf_scheduler::UserState);
                    }
                    // SAFETY: a prior poll's trap path populated
                    // `ctx.state` via `TrapContext::save_user_state`;
                    // the AS is re-activated and kernel state (TSS rsp0,
                    // GS) is still correct from first entry. Never
                    // returns — iretq resumes the saved user frame.
                    // SAFETY: Valid memory or trusted environment
                    unsafe { narf_scheduler::enter_user_mode_resume(this.ctx.state.get()) }
                }
                TaskState::Exited => unreachable!("guarded above"),
            }
        }
        #[cfg(target_arch = "x86_64")]
        narf_memory::beacon::paint(52, 0x0060_FF60); // pale green: post-trap, re-polled

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
        CURRENT_JMP.store(core::ptr::null_mut(), Ordering::Release);

        let reason = saved as u32;
        if reason == EXIT_REASON_EXITED {
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
                .ctx
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
    ctx: UserTaskCtx,
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
    /// Construct a fresh polling future for `process`. Hand to
    /// `narf_scheduler::spawn_user` to schedule it.
    pub fn new(process: crate::UserProcess) -> Self {
        Self {
            process,
            ctx: UserTaskCtx::new(),
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
    pub fn resume_with(process: crate::UserProcess, state: UserState) -> Self {
        let ctx = UserTaskCtx::new();
        // SAFETY: just constructed `ctx`; sole owner.
        unsafe {
            *ctx.state.get() = state;
        }
        Self {
            process,
            ctx,
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

        // sys_sleep park-via-deadline + throttle (mirrors x86_64 —
        // see the sibling poll body for the rationale).
        let deadline = this.ctx.sleep_deadline_ns.load(Ordering::Acquire);
        if deadline != 0 {
            let now = narf_scheduler::narf_time::monotonic_ns();
            // Break an infinite park on an async pending signal — see the
            // sibling poll body for the rationale.
            let signal_pending = deadline == u64::MAX
                && crate::handlers::is_signal_pending(crate::handlers::current_task_id());
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
            this.ctx.sleep_deadline_ns.store(0, Ordering::Release);
        }

        // sys_wait4 cooperative parking (mirrors x86_64 poll body).
        if this.ctx.wait_child_pending.load(Ordering::Acquire) {
            let want_pid = this.ctx.wait_child_want_pid.load(Ordering::Acquire);
            let status_ptr = this.ctx.wait_child_status_ptr.load(Ordering::Acquire);
            // Use the scheduler TaskId (set by CURRENT_TASK before this poll)
            // as the key to look up PENDING_EXITS. `sys_fork` stores the
            // parent's TaskId (`current_task_id()`) into PARENT_OF and
            // PENDING_EXITS, so the lookup key must also be the TaskId.
            let task_pid = crate::handlers::current_task_id();
            let mut child_status = 0i32;
            let reaped = call_wait_child_check(task_pid, want_pid, &mut child_status);
            if reaped > 0 {
                let is_waitid = this.ctx.wait_child_is_waitid.load(Ordering::Acquire);
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
                        let us = &mut *this.ctx.state.get();
                        us.x[0] = rax;
                    }
                }
                this.ctx.wait_child_pending.store(false, Ordering::Release);
                this.ctx
                    .wait_child_is_waitid
                    .store(false, Ordering::Release);
            } else {
                register_wait_child_waker(task_pid, cx.waker().clone());
                let mut child_status2 = 0i32;
                let reaped2 = call_wait_child_check(task_pid, want_pid, &mut child_status2);
                if reaped2 > 0 {
                    drop_wait_child_waker(task_pid);
                    let is_waitid = this.ctx.wait_child_is_waitid.load(Ordering::Acquire);
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
                            let us = &mut *this.ctx.state.get();
                            us.x[0] = rax;
                        }
                    }
                    this.ctx.wait_child_pending.store(false, Ordering::Release);
                    this.ctx
                        .wait_child_is_waitid
                        .store(false, Ordering::Release);
                } else {
                    return core::task::Poll::Pending;
                }
            }
        }

        let task_id = crate::handlers::current_task_id();
        register_user_task_ctx(task_id, &mut this.ctx as *mut _);

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
            notify_task_exited(this.process.pid.raw(), crate::handlers::current_task_id());
            this.state = TaskState::Exited;
            return core::task::Poll::Ready(());
        }

        // Publish per-task pointers the trap path consults.
        install_current(&mut this.ctx as *mut _);
        CURRENT_JMP.store(this.jmp.get(), Ordering::Release);

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
                    // SAFETY: Valid memory or trusted environment
                    unsafe { narf_scheduler::enter_user_mode_resume(this.ctx.state.get()) }
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
        CURRENT_JMP.store(core::ptr::null_mut(), Ordering::Release);

        let reason = saved as u32;
        if reason == EXIT_REASON_EXITED {
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
    let p = CURRENT_JMP.load(Ordering::Acquire);
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
    let p = CURRENT_JMP.load(Ordering::Acquire);
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
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[derive(Debug)]
pub struct UserTaskFuture {
    _process: crate::UserProcess,
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl UserTaskFuture {
    pub fn new(process: crate::UserProcess) -> Self {
        Self { _process: process }
    }

    pub fn resume_with(process: crate::UserProcess, _state: UserState) -> Self {
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
