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
use core::sync::atomic::{AtomicPtr, Ordering};

#[cfg(target_arch = "x86_64")]
pub use narf_scheduler::UserState;

/// Stub `UserState` for non-x86_64 arches so this module compiles
/// uniformly. The aarch64 EL0 ↔ EL1 round-trip with proper save/
/// restore lands separately; until then, this is just a typed
/// placeholder.
#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UserState {
    pub pc: u64, pub sp: u64, pub spsr: u64,
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
#[repr(C)]
pub struct UserTaskCtx {
    pub state:        UnsafeCell<UserState>,
    pub arch_jmp_buf: UnsafeCell<[u64; 8]>,
    /// Cell used by the trap handler to signal *why* it longjmp'd.
    /// Polling routine reads this after setjmp returns non-zero.
    pub exit_reason:  UnsafeCell<u32>,
}

// SAFETY: cells are accessed only from the polling routine and
// from the trap handler. Both run on the same CPU at any point in
// time (single-CPU cooperative); the trap handler runs to
// completion before the polling routine continues. SMP support
// will require a per-CPU slot rather than a global static.
unsafe impl Sync for UserTaskCtx {}

impl UserTaskCtx {
    /// Construct a fresh context with all state zeroed.
    pub fn new() -> Self {
        Self {
            state:        UnsafeCell::new(UserState::default()),
            arch_jmp_buf: UnsafeCell::new([0; 8]),
            exit_reason:  UnsafeCell::new(0),
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
pub const EXIT_REASON_EXITED:  u32 = 2;

/// Single-task slot the polling routine populates before transitioning
/// to user mode. Trap handlers consult this to find the calling
/// task's `UserTaskCtx`. SMP will replace this with a per-CPU
/// pointer; until then the cooperative single-CPU executor
/// guarantees only one task is ever in flight.
static CURRENT: AtomicPtr<UserTaskCtx> = AtomicPtr::new(core::ptr::null_mut());

/// Install `ctx` as the current polling target. Stored as a raw
/// pointer; the caller's `Pin<&mut UserTaskFuture>` keeps the
/// allocation alive across the user-mode round-trip.
pub fn install_current(ctx: *mut UserTaskCtx) {
    CURRENT.store(ctx, Ordering::Release);
}

/// Clear the current-task slot. Called on `Pending` / `Ready`
/// return so a stale pointer can't be picked up by an unrelated
/// trap.
pub fn clear_current() {
    CURRENT.store(core::ptr::null_mut(), Ordering::Release);
}

/// Trap-handler-side accessor: returns the currently-polling
/// `UserTaskCtx`, or `None` if no polling routine is in flight.
pub fn current_user_task() -> Option<*mut UserTaskCtx> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(p) }
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
static EXIT_HOOK:  AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the `Yield`-from-user-mode hook. Call once at boot per
/// CPU's polling executor.
pub fn install_yield_hook(hook: ExitHook) {
    YIELD_HOOK.store(hook as *mut (), Ordering::Release);
}

/// Install the `ExitTask`-from-user-mode hook.
pub fn install_exit_hook(hook: ExitHook) {
    EXIT_HOOK.store(hook as *mut (), Ordering::Release);
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_clear_hooks() {
    YIELD_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    EXIT_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    clear_current();
}

#[inline]
pub(crate) fn yield_hook() -> Option<ExitHook> {
    let p = YIELD_HOOK.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { core::mem::transmute::<*mut (), ExitHook>(p) }) }
}

#[inline]
pub(crate) fn exit_hook() -> Option<ExitHook> {
    let p = EXIT_HOOK.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { core::mem::transmute::<*mut (), ExitHook>(p) }) }
}
