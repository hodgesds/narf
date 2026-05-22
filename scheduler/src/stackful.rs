//! Stackful kernel tasks.
//!
//! Spec: `scheduler/specification/preemption.md` Phase 1b.
//!
//! Wraps a `Pin<Box<dyn Future>>` with a dedicated kernel stack
//! + a saved `KernelContext`, so the future's `poll()` runs on
//! the task's own stack instead of the executor's. The point is
//! NOT (yet) preemption — phase 1b is the foundation. Phase 2
//! adds the timer-driven preemption that's the actual fix for
//! the cooperative-async busy-loop wedge.
//!
//! With this in place, the executor can `kernel_switch` into a
//! task; the task polls its future to either `Ready` (done) or
//! `Pending` (yield); on yield, the task `kernel_switch`'es back
//! to the executor's saved context.
//!
//! ## Lifecycle
//!
//! 1. `KernelTask::new(future, stack_bytes)` — allocate a stack
//!    and seed `KernelContext::fresh` with the trampoline entry
//!    + a pointer to the task itself in r15.
//! 2. Executor calls `KernelTask::poll_to_yield(&mut self, exec_ctx)`:
//!    - Records `exec_ctx` so the task knows where to switch back.
//!    - Calls `kernel_switch(exec_ctx, &task.ctx)`.
//!    - Eventually returns when the task yields or completes.
//!    - Returns `Poll::Ready` if done, `Poll::Pending` otherwise.
//! 3. Task drop: stack, future, context all drop together.
//!
//! ## Stack layout
//!
//! ```text
//!  stack_top  ─►  ┌─────────────┐
//!                 │   padding   │  (16-byte alignment for the
//!                 │             │   ABI before any function call)
//!                 ├─────────────┤
//!  initial rsp ─► │   ...       │
//!                 │  task body  │
//!                 │  frames     │
//!                 │   ...       │
//!                 │             │  (~16 KiB default)
//!  stack_bottom─► └─────────────┘
//! ```
//!
//! Stack overflow: phase 1b uses a plain `Box<[u8]>` with no guard
//! page. Phase 3 adds a guard page via vmalloc.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

#[cfg(target_arch = "x86_64")]
use narf_arch::x86_64::kernel_ctx::{kernel_switch, KernelContext};

/// Trap frame layout matching `narf_frame::x86_64::trap::TrapFrame`.
/// Re-declared here because scheduler can't depend on frame (frame
/// depends on scheduler). A const-assert pins layout equality at
/// the `frame` end; drift on either side fails the build.
///
/// Order follows `frame::x86_64::trap_entry.S`'s reverse-push +
/// CPU-pushed tail.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Default time slice for preemptive tasks. 10 ms ≈ 33 M cycles on
/// a 3.3 GHz Zen2. Matches Linux's `CONFIG_HZ_100`-ish granularity
/// and is short enough that one busy-looping task can't hold the
/// CPU long enough to be visible.
pub const DEFAULT_SLICE_CYCLES: u64 = 33_000_000;

/// Vector the trap handler dispatches preemption on. Matches
/// `narf_interrupts::VECTOR_TIMER` (32) — re-declared here to
/// avoid the dep cycle.
pub const PREEMPT_VECTOR: u64 = 32;

/// Default per-task kernel stack size. 16 KiB matches the TSS.rsp0
/// stack the kernel uses for user→kernel trap entry; deep enough
/// for any in-kernel future poll path that doesn't do unbounded
/// recursion.
pub const DEFAULT_KERNEL_STACK_BYTES: usize = 16 * 1024;

/// Per-CPU currently-running stackful task. Set by
/// `poll_to_yield` immediately before `kernel_switch`-in;
/// cleared after the switch-back. The trap-handler hook reads
/// this to decide whether the interrupted code is a stackful
/// task eligible for preemption.
///
/// Single global for phase 2 (BSP-only); phase 3 promotes to a
/// per-CPU array.
pub static CURRENT_STACKFUL_TASK: AtomicPtr<KernelTask> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
const fn zeroed_trap_frame() -> TrapFrame {
    TrapFrame {
        r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0,
        vector: 0, error_code: 0,
        rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

/// A future + the kernel-side context to run it on its own stack.
///
/// Built around `Pin<Box<dyn Future>>` so existing async functions
/// continue to compile against this without rewrite. The
/// "stackful" aspect is the *poll* layer: the executor switches
/// to a dedicated stack before calling `future.poll(cx)`.
pub struct KernelTask {
    /// The future being driven. Pinned in a Box so its address is
    /// stable across poll calls.
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    /// Per-task kernel stack. Box<[u8]> for automatic drop. Size
    /// captured at `new()` time; phase 1b doesn't grow stacks.
    stack: Box<[u8]>,
    /// Saved register state. Initialised by `KernelContext::fresh`
    /// to land the first kernel_switch on `trampoline_entry`.
    ctx: KernelContext,
    /// Pointer to the executor's `KernelContext`. The executor
    /// stores its own ctx address here before switching in; the
    /// task reads it back to know where to switch when yielding.
    /// AtomicPtr because the task and executor are on different
    /// stacks but the same CPU at any one time (phase 1b is BSP
    /// single-CPU).
    exec_ctx: AtomicPtr<KernelContext>,
    /// True once the future returns `Poll::Ready`. The trampoline
    /// loop checks this after yielding; if the executor schedules
    /// the task again after completion (shouldn't happen, but
    /// defensive), the trampoline just spins.
    completed: AtomicBool,
    /// TSC cycle count when the current `poll_to_yield` began.
    /// The trap handler hook compares against this to decide
    /// whether the task's slice has expired. Updated by
    /// `poll_to_yield` each entry.
    tsc_started: AtomicU64,
    /// Per-task time slice in TSC cycles. Default
    /// `DEFAULT_SLICE_CYCLES`. Set via `with_slice_cycles` at
    /// spawn time for drivers that need bigger slices.
    slice_cycles: AtomicU64,
    /// Opt-out: when true the trap-handler hook skips preempting
    /// this task. Use for drivers that hold hardware locks across
    /// an `.await`-free critical section.
    no_preempt: AtomicBool,
    /// Saved trap frame when the task was preempted. The
    /// preempt_resume_stub uses this to IRET back to the exact
    /// instruction the LAPIC timer interrupted. UnsafeCell because
    /// the trap-handler hook needs raw write access from inside
    /// an IRQ context (no Mutex).
    saved_trap_frame: UnsafeCell<TrapFrame>,
    /// Set true by the trap-handler hook when it rewrites the
    /// frame.rip to preempt_yield_stub. Read by
    /// `kernel_switch` resume path to choose `kernel_switch`-restore
    /// vs IRET-restore.
    preempted: AtomicBool,
}

// SAFETY: KernelTask is single-CPU for phase 2 (BSP-only). The
// UnsafeCell is written by the trap-handler hook which runs in
// IRQ context on the same CPU as the executor. No cross-CPU
// access in phase 2.
unsafe impl Send for KernelTask {}
unsafe impl Sync for KernelTask {}

impl core::fmt::Debug for KernelTask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelTask")
            .field("stack_bytes", &self.stack.len())
            .field("ctx", &self.ctx)
            .field("completed", &self.completed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl KernelTask {
    /// Allocate a stack + initial context for `future`. The first
    /// `poll_to_yield` call hands control to `trampoline_entry`,
    /// which calls `task_body_rust` with `self` in `r15`.
    pub fn new<F>(future: F) -> Box<Self>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self::with_stack_size(future, DEFAULT_KERNEL_STACK_BYTES)
    }

    /// Same as `new` but with a custom stack size. Must be ≥ 4 KiB
    /// (one page) and 16-byte aligned. Caller-driven for drivers
    /// that genuinely need deeper stacks.
    pub fn with_stack_size<F>(future: F, stack_bytes: usize) -> Box<Self>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        assert!(stack_bytes >= 4096, "kernel stack must be ≥ 4 KiB");
        assert!(stack_bytes & 0xF == 0, "kernel stack must be 16-byte aligned");

        // Allocate the stack on the heap so it's stable across
        // moves (we're going to point r15 at the task itself, and
        // rsp at this stack — both pointers must stay valid).
        let stack: Box<[u8]> = alloc::vec![0u8; stack_bytes].into_boxed_slice();

        // We'll fill in ctx after the Box exists (need its
        // address). Start with a placeholder.
        let mut me = Box::new(KernelTask {
            future: Box::pin(future),
            stack,
            ctx: KernelContext::default(),
            exec_ctx: AtomicPtr::new(core::ptr::null_mut()),
            completed: AtomicBool::new(false),
            tsc_started: AtomicU64::new(0),
            slice_cycles: AtomicU64::new(DEFAULT_SLICE_CYCLES),
            no_preempt: AtomicBool::new(false),
            saved_trap_frame: UnsafeCell::new(zeroed_trap_frame()),
            preempted: AtomicBool::new(false),
        });

        // Stack top = highest byte addr + 1, then mask down to
        // 16-byte alignment. The ABI requires rsp be 16-byte
        // aligned just before a `call` instruction (which then
        // pushes the 8-byte return address, making it 8-byte
        // aligned at the callee's prologue). Our trampoline runs
        // without a `call` — `kernel_switch` does a `jmp rcx` to
        // it — so the entry sees rsp as 16-aligned, which is what
        // the SysV ABI wants for a fresh function entry.
        let stack_top = (me.stack.as_mut_ptr() as u64)
            .wrapping_add(me.stack.len() as u64)
            & !0xFu64;

        // Smuggle the task pointer in via r15 (callee-saved
        // register, survives the asm restore). The trampoline
        // moves it to rdi for the Rust-side call.
        let task_ptr_as_u64 = &*me as *const KernelTask as u64;

        #[cfg(target_arch = "x86_64")]
        {
            me.ctx = KernelContext::fresh(
                stack_top,
                trampoline_entry as u64,
                task_ptr_as_u64,
            );
        }
        let _ = stack_top; // silence warning on aarch64 stub

        me
    }

    /// Resume the task. Switches to its stack and lets it run
    /// until it yields or completes. Returns `Poll::Ready` on
    /// completion, `Poll::Pending` otherwise.
    ///
    /// `exec_ctx` is the executor's `KernelContext`. The task
    /// will switch back into it when yielding. The reference's
    /// lifetime covers the duration of this call.
    ///
    /// # Safety
    /// - Must be called on the same CPU the task was created on
    ///   (phase 1b is BSP-only; phase 3 generalises).
    /// - No concurrent `poll_to_yield` for the same task. The
    ///   AtomicPtr/AtomicBool make in-CPU re-entry detectable
    ///   in debug builds; the precondition is the caller's.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn poll_to_yield(
        &mut self,
        exec_ctx: &mut KernelContext,
    ) -> Poll<()> {
        // Publish exec_ctx so the task can find it on yield.
        self.exec_ctx
            .store(exec_ctx as *mut _, Ordering::Release);
        // Record when this slice started — the trap-handler
        // preempt hook reads `tsc_started` to decide whether
        // we've used our slice.
        self.tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
        // Publish self to the per-CPU current-task slot so the
        // trap-handler hook can find us on a LAPIC timer fire.
        CURRENT_STACKFUL_TASK.store(self as *mut _, Ordering::Release);
        // SAFETY: ctx + exec_ctx both live for the duration of
        // this call; the task's stack was allocated by us and is
        // still alive; the trampoline_entry symbol is in this
        // crate's code segment.
        unsafe { kernel_switch(exec_ctx as *mut _, &self.ctx) };
        // ── We are resumed here when the task yields back ──
        // Clear CURRENT_STACKFUL_TASK so the next preempt-hook
        // fire doesn't think a stackful task is still active.
        CURRENT_STACKFUL_TASK.store(core::ptr::null_mut(), Ordering::Release);
        self.exec_ctx.store(core::ptr::null_mut(), Ordering::Release);
        if self.completed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Mark this task as non-preemptible. The trap-handler hook
    /// will skip it regardless of slice expiry. Use for drivers
    /// that hold hardware locks across an `.await`-free region.
    pub fn set_no_preempt(&self, v: bool) {
        self.no_preempt.store(v, Ordering::Release);
    }

    /// Set the per-task TSC time slice. Default is
    /// `DEFAULT_SLICE_CYCLES`. Larger slices reduce preemption
    /// overhead at the cost of latency.
    pub fn set_slice_cycles(&self, cycles: u64) {
        self.slice_cycles.store(cycles, Ordering::Release);
    }

    /// Build a no-op `Waker` for tasks that don't have a real
    /// cross-task wake mechanism yet. Phase 1b doesn't need
    /// wakers (the executor re-polls every round); phase 2 will
    /// integrate with the existing `Slot::awake` flag.
    fn no_op_waker() -> Waker {
        use core::task::{RawWaker, RawWakerVTable};
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        // SAFETY: VTABLE is 'static; the data ptr is null but
        // never dereferenced by the no-op callbacks.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }
}

// ── Task entry trampoline + Rust-side body ─────────────────────────
//
// `trampoline_entry` is the address `KernelContext::fresh` sets
// as `rip`. On the first `kernel_switch` into the task, the asm
// `jmp rcx` lands here with `r15 = task pointer` (the smuggled
// arg). We move it to `rdi` and call into Rust.
//
// SAFETY: this entry runs WITHOUT a return address on the stack
// — the rsp the asm restored points at the freshly-allocated
// stack's top. There's nowhere to return to, so the body must
// never return. `unreachable_unchecked` would also work; we
// halt-spin defensively if Rust's panic-on-return-from-! is
// ever bypassed.

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn trampoline_entry() -> ! {
    use core::arch::naked_asm;
    naked_asm!(
        // r15 = task ptr (smuggled by KernelContext::fresh).
        // Move to rdi for the SysV calling convention.
        "mov rdi, r15",
        // Re-establish 16-byte alignment for the ABI. The CPU is
        // currently at "16-aligned rsp" (no return PC has been
        // pushed). A `call` here would push 8 bytes, landing
        // body at "8-byte rsp pre-prologue", which is fine.
        "call {body}",
        // Body should never return — if it does, halt.
        "ud2",
        body = sym task_body_rust,
    );
}

/// The body of every stackful kernel task. Polls the future,
/// yields back to the executor when it returns Pending, marks
/// `completed = true` when it returns Ready then yields one
/// last time (so the executor can drop the task).
#[cfg(target_arch = "x86_64")]
extern "C" fn task_body_rust(task: *mut KernelTask) -> ! {
    // SAFETY: `task` was set by `KernelTask::new` from a `Box::leak`-
    // equivalent (we own the box via `Box<KernelTask>`; the executor
    // holds it during the switch + we get a &mut here as the only
    // active reference on this stack).
    let task = unsafe { &mut *task };

    loop {
        // Build a waker. Phase 1b uses a no-op; phase 2 binds it
        // to the executor's per-slot `awake` flag.
        let waker = KernelTask::no_op_waker();
        let mut cx = Context::from_waker(&waker);
        let result = task.future.as_mut().poll(&mut cx);
        match result {
            Poll::Ready(()) => {
                task.completed.store(true, Ordering::Release);
                // Fall through and yield one last time — the
                // executor checks `completed` after we yield and
                // drops the slot.
            }
            Poll::Pending => {}
        }
        // Yield back to the executor. We pull the exec_ctx pointer
        // out atomically — the executor populated it just before
        // switching us in.
        let exec_ctx = task.exec_ctx.load(Ordering::Acquire);
        if exec_ctx.is_null() {
            // Shouldn't happen — the executor is required to set
            // exec_ctx before switching in. Halt-spin defensively.
            loop {
                core::hint::spin_loop();
            }
        }
        // SAFETY: exec_ctx outlives this call (executor's stack
        // is alive in its `poll_to_yield`).
        unsafe { kernel_switch(&mut task.ctx, exec_ctx) };
        // ── We resume here when the executor switches us back ──
        if task.completed.load(Ordering::Acquire) {
            // Defensive: the executor should have dropped us
            // after `completed` was observed; if not, spin
            // rather than re-poll a completed future (UB per
            // the Future contract).
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

// ── Trap-handler hook ─────────────────────────────────────────────
//
// Called from `narf_frame::x86_64::trap::rust_trap_handler` at the
// top of vector-32 (LAPIC timer) dispatch. If a stackful task is
// currently running on this CPU AND its slice has expired AND
// preemption isn't opt-ed out AND the trap source is CPL=0, save
// the full trap frame into the task and rewrite `frame.rip` to
// point at `preempt_yield_stub`. The existing trap-exit IRET
// then lands on the stub instead of the original task code.
//
// Returns `true` iff the frame was rewritten (caller can short-
// circuit any further work after that).

/// Selector + DPL test: CPL=0 means the kernel was interrupted
/// while running, which is the only case we preempt. CPL=3 means
/// a user task was running — user preemption goes through the
/// existing user_task::poll machinery, not this hook.
#[inline]
const fn cpl_zero(cs: u64) -> bool {
    (cs & 3) == 0
}

/// Inspect a trap frame at LAPIC timer entry; if it's a
/// preemptable stackful task, redirect IRET into the yield stub.
///
/// # Safety
/// - Must be called from within `rust_trap_handler` with the
///   actual on-stack TrapFrame. Caller passes `&mut TrapFrame`
///   that's part of the trap.S-pushed frame.
/// - `narf-frame`'s TrapFrame layout must match scheduler's
///   `TrapFrame` declared above — there's a const-assert in
///   `narf-frame` that enforces this.
#[cfg(target_arch = "x86_64")]
pub unsafe fn try_preempt(frame: &mut TrapFrame) -> bool {
    if frame.vector != PREEMPT_VECTOR {
        return false;
    }
    if !cpl_zero(frame.cs) {
        return false; // trapped from user mode; not our path
    }
    let task_ptr = CURRENT_STACKFUL_TASK.load(Ordering::Acquire);
    if task_ptr.is_null() {
        return false; // no stackful task currently polling
    }
    // SAFETY: CURRENT_STACKFUL_TASK is only set by an in-progress
    // `poll_to_yield` whose caller still holds the Box alive; the
    // pointer remains valid until poll_to_yield clears it.
    let task = unsafe { &*task_ptr };
    if task.no_preempt.load(Ordering::Acquire) {
        return false;
    }
    let started = task.tsc_started.load(Ordering::Acquire);
    let slice = task.slice_cycles.load(Ordering::Acquire);
    let now = narf_time::now_cycles();
    if now.saturating_sub(started) < slice {
        return false; // task hasn't used its slice yet
    }
    // Save the full trap frame so preempt_resume_stub can IRET
    // back to the exact interrupted instruction.
    // SAFETY: UnsafeCell write; we're the only writer on this CPU
    // (single-CPU phase 2); concurrent readers are blocked while
    // we're in the trap handler.
    unsafe {
        core::ptr::write_volatile(task.saved_trap_frame.get(), *frame);
    }
    task.preempted.store(true, Ordering::Release);

    // Bisect: try_preempt detects the slice expiry and saves the
    // trap frame, but the IRET-redirect rewrite is gated by a
    // run-time switch so we can flip it on/off via xtask args
    // (or a CLAUDE.md tweak) without rebuilding the bisect step.
    // Once the rewrite is confirmed-stable on hardware, the gate
    // becomes a constant `true`.
    if !PREEMPT_REWRITE_ENABLED.load(Ordering::Acquire) {
        return true;
    }

    // Clear CURRENT_STACKFUL_TASK BEFORE rewriting frame.rip.
    // The stub reads `task_ptr` from PENDING_YIELD_TASK below,
    // so the global isn't needed once stashed. Clearing prevents
    // a subsequent timer fire (mid-stub-execution) from
    // re-entering try_preempt and rewriting frame.rip back to
    // the stub — an infinite preemption-rewrite loop.
    CURRENT_STACKFUL_TASK.store(core::ptr::null_mut(), Ordering::Release);
    PENDING_YIELD_TASK.store(task_ptr as *mut KernelTask, Ordering::Release);

    // Rewrite frame.rip → preempt_yield_stub. The trap-exit IRET
    // carries the rewritten RIP, lands on the stub at CPL=0 on
    // the task's own stack with task's pre-trap RSP. The stub is
    // a naked entry that ALIGNS rsp before calling the Rust body
    // (the IRET-time rsp can be 16- or 8-aligned depending on
    // where in the task the timer fired; SysV ABI requires
    // rsp%16==0 just before the call instruction).
    frame.rip = preempt_yield_stub as u64;
    // RFLAGS: IF=1 (interrupts re-enabled at stub entry so
    // subsequent timer ticks can still preempt OTHER tasks
    // — CURRENT_STACKFUL_TASK is null so they early-return),
    // TF=0 (no single-step), reserved bit 1 set.
    frame.rflags = (frame.rflags & !0x100) | 0x200 | 0x2;
    true
}

/// Run-time switch for the IRET-redirect half of the preempt
/// hook. When `false`, try_preempt still detects slice-expiry
/// and saves the trap frame but does NOT rewrite frame.rip —
/// useful as a bisect lever while the IRET landing is debugged.
/// Default `false` until we've fully validated the landing on
/// both target laptops (Phoenix HawkPoint1 + Zen2 Renoir).
pub static PREEMPT_REWRITE_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable the IRET-redirect rewrite. Call once after boot when
/// the kernel is ready to take preemption events. Currently
/// gated off pending root-cause of an IRET landing exception.
pub fn enable_preempt_rewrite() {
    PREEMPT_REWRITE_ENABLED.store(true, Ordering::Release);
}

/// Set by try_preempt when it redirects to preempt_yield_stub;
/// read by the stub to find which task to switch back from.
/// Single-CPU phase 2; phase 3 makes this per-CPU.
static PENDING_YIELD_TASK: AtomicPtr<KernelTask> = AtomicPtr::new(core::ptr::null_mut());

// ── Yield + Resume stubs ─────────────────────────────────────────
//
// `preempt_yield_stub` runs at CPL=0, on the task's kernel stack,
// just after the timer ISR's IRET. The stub:
//   1. Reads CURRENT_STACKFUL_TASK to find which task we are.
//   2. Sets up task.ctx so the next kernel_switch-INTO this task
//      lands at preempt_resume_stub (which restores the saved
//      trap frame and IRETs).
//   3. Calls kernel_switch(&task.ctx, exec_ctx) — switches back
//      to the cooperative executor.
//
// Written as a regular Rust fn (no naked asm needed — the
// trap-handler hook arranged for the trap-exit IRET to land
// here as a normal function call site, NOT a context-switch
// boundary requiring callee-saved-only).

/// Stub that runs at CPL=0 on the task's kernel stack after the
/// timer ISR's IRET redirects here (the trap-handler hook
/// rewrote `frame.rip = preempt_yield_stub`).
///
/// Implemented as a naked entry because the IRET-time rsp
/// alignment is unknown — the LAPIC timer can fire at any
/// instruction in the task. SysV requires `rsp%16==0` just
/// before a `call`, so we `and rsp, -16` before invoking the
/// Rust body. The cost is up to 15 bytes of "lost" stack space
/// which we don't care about: the body abandons the task's
/// in-progress poll stack anyway, and the next switch-in resets
/// rsp to the task's stack top via `trampoline_entry`.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn preempt_yield_stub() -> ! {
    use core::arch::naked_asm;
    naked_asm!(
        // Align rsp DOWN to a 16-byte boundary. After this,
        // rsp%16==0; the upcoming `call` pushes 8 bytes of
        // return address making it 8-aligned at body entry,
        // which is the SysV-AMD64 ABI contract.
        "and rsp, -16",
        "call {body}",
        // Body should never return.
        "ud2",
        body = sym preempt_yield_stub_body,
    );
}

/// Lossy-preempt strategy: futures are stackless, so we don't
/// need to preserve the kernel stack precisely — the future's
/// logical state lives in its `Pin<Box<dyn Future>>`. Resetting
/// task.ctx to land at `trampoline_entry` on a fresh stack
/// effectively says "abandon the current poll's intermediate
/// stack frames; on next switch-in, re-poll the future from
/// whatever state it's in." The future itself doesn't lose
/// progress — it just re-enters its current poll body.
///
/// We `kernel_switch` to the executor with a SCRATCH context
/// for the save half. The current task's register state at
/// preempt time is abandoned; only the future's heap state
/// survives, which is what matters for correctness.
#[cfg(target_arch = "x86_64")]
extern "C" fn preempt_yield_stub_body() -> ! {
    // Read the task pointer that try_preempt stashed before
    // rewriting frame.rip. CURRENT_STACKFUL_TASK was already
    // cleared by try_preempt so timer fires during this stub's
    // execution don't re-preempt.
    let task_ptr = PENDING_YIELD_TASK.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if task_ptr.is_null() {
        loop {
            core::hint::spin_loop();
        }
    }
    // SAFETY: CURRENT_STACKFUL_TASK was set by the in-progress
    // poll_to_yield; the Box stays alive until that call returns.
    let task = unsafe { &mut *task_ptr };

    // Reset task.ctx so the NEXT switch-in lands at the
    // trampoline (which re-polls the future). Use the task's
    // own stack top — abandoning whatever intermediate frames
    // the preempted poll() had pushed.
    let stack_top = task
        .stack
        .as_mut_ptr()
        .wrapping_add(task.stack.len()) as u64
        & !0xFu64;
    task.ctx = KernelContext::fresh(
        stack_top,
        trampoline_entry as u64,
        task_ptr as u64,
    );
    task.preempted.store(true, Ordering::Release);

    let exec_ctx = task.exec_ctx.load(Ordering::Acquire);
    if exec_ctx.is_null() {
        loop {
            core::hint::spin_loop();
        }
    }

    // Switch back to executor. Use a scratch ctx for the save
    // half — we don't care about preserving this stub's regs
    // because nothing ever switches back into THIS stack
    // address (next switch-in lands at trampoline_entry with
    // rsp = stack_top, abandoning intermediate frames).
    let mut scratch = KernelContext::default();
    // SAFETY: exec_ctx valid (set by poll_to_yield); scratch is
    // a local that survives the call. The switch's `jmp rcx`
    // lands on the executor's saved rip; this frame is
    // abandoned per the comment above.
    unsafe {
        kernel_switch(&mut scratch, exec_ctx);
    }
    loop {
        core::hint::spin_loop();
    }
}

// ── Cooperative-executor adapter ──────────────────────────────────
//
// Wraps a `KernelTask` in a `Future` so the existing
// `run_until_empty` cooperative executor can drive it without
// any restructuring. The adapter's `poll()` allocates an
// `exec_ctx` on the cooperative executor's stack, switches into
// the stackful task, and forwards whatever the task returned.
//
// Phase 1c: this plumbing alone does NOT preempt busy-loops —
// if the inner future busy-loops on the task's stack we still
// wedge. Phase 2 (timer-driven preemption) is what wins; this
// adapter sets up the structural slot the timer ISR will use to
// find the task and save its trap-frame state into.

/// Future that drives a `KernelTask` from inside the cooperative
/// executor. Spawned via `spawn_stackful` — `Future` impl below
/// just calls `poll_to_yield` and forwards the result.
pub struct StackfulAdapter {
    inner: Box<KernelTask>,
}

impl core::fmt::Debug for StackfulAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StackfulAdapter")
            .field("inner", &self.inner)
            .finish()
    }
}

impl StackfulAdapter {
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            inner: KernelTask::new(future),
        }
    }

    /// Construct with explicit options (slice + no_preempt +
    /// stack size). Used by `spawn_stackful_with_options`.
    /// Caller must invoke `apply_options` after construction to
    /// commit slice/no_preempt to the inner task — kept as a
    /// separate step so the StackfulOptions struct can stay
    /// `Copy`.
    pub fn with_options<F>(future: F, opts: crate::StackfulOptions) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let inner = KernelTask::with_stack_size(future, opts.stack_bytes);
        let me = Self { inner };
        // Cache opts on the adapter for `apply_options` — keep
        // a simple atomic-set pattern; opts are tiny.
        me.inner.set_slice_cycles(opts.slice_cycles);
        me.inner.set_no_preempt(opts.no_preempt);
        me
    }

    /// Apply any pending option changes that haven't been
    /// committed to the inner KernelTask. `with_options` already
    /// applies on construction; this method is a no-op kept for
    /// API symmetry with future mutator paths.
    pub fn apply_options(&mut self) {
        // Currently a no-op (with_options applies inline). Kept
        // so callers in `lib.rs` have a stable post-construction
        // hook.
    }
}

impl Future for StackfulAdapter {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: `Self` is structurally pinned, but we never
        // move `inner` (it's behind a `Box`); we re-borrow as
        // `&mut` to call `poll_to_yield`. The exec_ctx lives on
        // the executor's stack frame for the duration of this
        // poll — the task switches back before `poll` returns,
        // so exec_ctx never escapes.
        #[cfg(target_arch = "x86_64")]
        {
            let this = unsafe { self.get_unchecked_mut() };
            let mut exec_ctx = KernelContext::default();
            // SAFETY: single-threaded; this poll() is the only
            // active caller of this KernelTask.
            let result = unsafe { this.inner.poll_to_yield(&mut exec_ctx) };
            if result.is_pending() {
                // Preempt-yield doesn't carry "wait for event X"
                // semantics — the task is willing-and-able to keep
                // running, the timer just took its slice away. Re-
                // arm the executor's waker so we get re-polled on
                // the next round. Without this, the slot's `awake`
                // flag stays false and the task sits forever.
                cx.waker().wake_by_ref();
            }
            result
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // aarch64 has no kernel_ctx primitive yet — fall
            // back to immediate completion. Phase 2 + arm64
            // port follows the same shape.
            Poll::Ready(())
        }
    }
}

// Tests are inline below — same gating as the kernel_ctx smokes.

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A future that increments a counter and returns Ready
    /// immediately. Used to verify the stackful path completes
    /// a trivial future in one shot.
    struct TrivialFuture {
        counter: &'static AtomicU32,
    }
    impl Future for TrivialFuture {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            self.counter.fetch_add(1, Ordering::Release);
            Poll::Ready(())
        }
    }

    /// Drive a trivial future to completion via the stackful
    /// path. Verifies kernel_switch round-trips the executor ↔
    /// task transitions correctly.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_trivial_future_completes() -> TestResult {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        COUNTER.store(0, Ordering::Release);
        let mut task = KernelTask::new(TrivialFuture { counter: &COUNTER });
        let mut exec_ctx = KernelContext::default();
        // SAFETY: single-threaded test; no preemption.
        let result = unsafe { task.poll_to_yield(&mut exec_ctx) };
        if result != Poll::Ready(()) {
            return TestResult::Fail("expected Ready on first poll");
        }
        if COUNTER.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("counter not bumped");
        }
        TestResult::Pass
    }

    /// A future that returns Pending the first N times, then
    /// Ready. Verifies the executor ↔ task switch cycle works
    /// across multiple yields.
    struct CountdownFuture {
        remaining: u32,
        counter: &'static AtomicU32,
    }
    impl Future for CountdownFuture {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            self.counter.fetch_add(1, Ordering::Release);
            if self.remaining == 0 {
                Poll::Ready(())
            } else {
                self.remaining -= 1;
                Poll::Pending
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_multi_yield_then_complete() -> TestResult {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        COUNTER.store(0, Ordering::Release);
        let mut task = KernelTask::new(CountdownFuture {
            remaining: 3,
            counter: &COUNTER,
        });
        let mut exec_ctx = KernelContext::default();
        // First three polls should be Pending, fourth Ready.
        for expected_count in 1..=3 {
            // SAFETY: same.
            let r = unsafe { task.poll_to_yield(&mut exec_ctx) };
            if r != Poll::Pending {
                return TestResult::Fail("expected Pending while counter < 4");
            }
            if COUNTER.load(Ordering::Acquire) != expected_count {
                return TestResult::Fail("counter mismatch on Pending iteration");
            }
        }
        let r = unsafe { task.poll_to_yield(&mut exec_ctx) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready after countdown");
        }
        if COUNTER.load(Ordering::Acquire) != 4 {
            return TestResult::Fail("final counter wrong");
        }
        TestResult::Pass
    }

    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_trivial_future_completes
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_multi_yield_then_complete
    );
}
