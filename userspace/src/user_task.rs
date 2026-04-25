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

#[cfg(target_arch = "x86_64")]
pub use narf_scheduler::JmpBuf;

/// Stub `JmpBuf` for non-x86_64 arches. The aarch64 EL0/EL1 polling
/// round-trip lands separately.
#[cfg(not(target_arch = "x86_64"))]
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
}

/// Non-x86 stub. The polling-future round-trip on aarch64 lands
/// alongside the EL0 ↔ EL1 save/restore primitives.
#[cfg(not(target_arch = "x86_64"))]
pub fn install_user_task_hooks() {}

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
    ctx:     UserTaskCtx,
    jmp:     UnsafeCell<JmpBuf>,
    state:   TaskState,
    /// Snapshot of the kernel's CR3 captured on the first poll so
    /// we can restore it on the return path. `None` until the first
    /// poll runs.
    saved_cr3: core::cell::Cell<Option<u64>>,
}

#[cfg(target_arch = "x86_64")]
impl core::fmt::Debug for UserTaskFuture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserTaskFuture")
            .field("pid",   &self.process.pid)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

// SAFETY: the future is polled only on a single CPU at a time
// (single-CPU cooperative executor); the UnsafeCell-wrapped JmpBuf
// is only written by `poll` (between the install_current and the
// setjmp) and only read by the longjmp targeting it. The hooks
// reach it via the global CURRENT_JMP atomic, so cross-thread
// publication is the atomic, not the cell. The future never escapes
// the executor's `Pin<Box<...>>`.
#[cfg(target_arch = "x86_64")]
unsafe impl Send for UserTaskFuture {}

#[cfg(target_arch = "x86_64")]
impl UserTaskFuture {
    /// Construct a fresh polling future for `process`. The future
    /// is not yet on any ready queue — hand it to
    /// `narf_scheduler::spawn_user` to schedule it.
    pub fn new(process: crate::UserProcess) -> Self {
        Self {
            process,
            ctx:       UserTaskCtx::new(),
            jmp:       UnsafeCell::new(JmpBuf::default()),
            state:     TaskState::Initial,
            saved_cr3: core::cell::Cell::new(None),
        }
    }

    /// Borrow the inner process — useful for inspection from tests.
    pub fn process(&self) -> &crate::UserProcess { &self.process }

    /// Inspect the current lifecycle stamp.
    pub fn task_state(&self) -> TaskState { self.state }
}

#[cfg(target_arch = "x86_64")]
impl core::future::Future for UserTaskFuture {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        // Pin guarantees we're not moved between polls. We need
        // &mut access to the inner struct so the hooks see a stable
        // address for `self.ctx` and `self.jmp`.
        // SAFETY: we don't move out of the Pin; we only project &mut
        // to fields whose address stability we own.
        let this = unsafe { self.get_unchecked_mut() };

        if this.state == TaskState::Exited {
            // Defensive — the executor drops Ready slots, so this
            // shouldn't be reached, but if a future somehow gets
            // re-polled after Ready it stays Ready.
            return core::task::Poll::Ready(());
        }

        // Snapshot kernel CR3 once, on the first poll. Subsequent
        // polls re-activate the user AS, so we always land back on
        // the kernel root via the trap-back / cleanup path.
        if this.saved_cr3.get().is_none() {
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

        // Interrupts off across the iretq. The trap handler
        // re-enables them on its swapgs path; the hook + longjmp
        // path keeps IF=0 (per the kernel-test build's "no LAPIC
        // timer → leaving IF=1 turns the next halt_until_irq into a
        // wedge" rationale captured in commit 401b073).
        // SAFETY: cli has no memory effect.
        unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)); }

        // setjmp. On the initial call returns 0; the hooks longjmp
        // back here with a non-zero EXIT_REASON_*.
        // SAFETY: jmp is a valid, properly-aligned JmpBuf for the
        // duration of this `poll` body (Pin guarantees stable
        // address; UnsafeCell gives interior mutability without
        // creating an aliased &mut while the longjmp executes).
        let saved = unsafe { narf_scheduler::setjmp(this.jmp.get()) };

        if saved == 0 {
            match this.state {
                TaskState::Initial => {
                    this.state = TaskState::Running;
                    let entry  = this.process.entry.0.as_u64();
                    let rsp    = this.process.stack_top.as_u64();
                    // SAFETY: the AS is activated and the user
                    // mappings cover entry + rsp by construction
                    // (load_user_process_with mapped them). Never
                    // returns — control reaches CPL=3.
                    unsafe { narf_scheduler::enter_user_mode(entry, rsp) }
                }
                TaskState::Running => {
                    // SAFETY: a prior poll's trap path populated
                    // ctx.state via TrapContext::save_user_state.
                    // The AS is re-activated and the kernel state
                    // (TSS rsp0, GS) is still correct from the
                    // first entry.
                    unsafe {
                        narf_scheduler::enter_user_mode_resume(this.ctx.state.get())
                    }
                }
                TaskState::Exited => unreachable!("guarded above"),
            }
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
            this.state = TaskState::Exited;
            core::task::Poll::Ready(())
        } else {
            // EXIT_REASON_YIELDED or any unknown reason — repoll.
            // Wake immediately so the executor visits us again on
            // the next round.
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    }
}

/// Non-x86 stub. The polling future on aarch64 follows the EL0/EL1
/// save/restore primitives.
#[cfg(not(target_arch = "x86_64"))]
#[derive(Debug)]
pub struct UserTaskFuture { _process: crate::UserProcess }

#[cfg(not(target_arch = "x86_64"))]
impl UserTaskFuture {
    pub fn new(process: crate::UserProcess) -> Self { Self { _process: process } }
}

#[cfg(not(target_arch = "x86_64"))]
impl core::future::Future for UserTaskFuture {
    type Output = ();
    fn poll(self: core::pin::Pin<&mut Self>, _cx: &mut core::task::Context<'_>) -> core::task::Poll<()> {
        // aarch64 polling round-trip not yet implemented.
        core::task::Poll::Ready(())
    }
}
