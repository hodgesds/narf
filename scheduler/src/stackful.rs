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
/// this (indexed by the trapped CPU's id) to decide whether
/// the interrupted code is a stackful task eligible for
/// preemption.
///
/// SMP-correct: each CPU has its own slot. Without this, two
/// CPUs concurrently polling stackful tasks would race on a
/// single shared slot and try_preempt could observe the other
/// CPU's task pointer — a real fault waiting to happen.
struct PerCpuTaskPtr {
    inner: [AtomicPtr<KernelTask>; narf_lib::percpu::MAX_CPUS],
}
static CURRENT_STACKFUL_TASK: PerCpuTaskPtr = PerCpuTaskPtr {
    inner: [const { AtomicPtr::new(core::ptr::null_mut()) };
        narf_lib::percpu::MAX_CPUS],
};

#[inline]
fn this_cpu() -> usize {
    let c = narf_lib::percpu::current_cpu();
    if c < narf_lib::percpu::MAX_CPUS {
        c
    } else {
        0
    }
}

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
    /// Executor-supplied waker, plumbed in by `poll_to_yield` on
    /// each entry. `task_body_rust` builds a `Context` around this
    /// waker so the inner future's `cx.waker().wake_by_ref()` (e.g.
    /// from `yield_now()`) re-arms the correct executor slot. With
    /// a no-op waker, `yield_now` quietly drops the wake call and
    /// the slot's `awake` flag never flips back to true — the task
    /// returns Pending and then sits dormant forever.
    /// `IrqSafeSpinLock<Option<Waker>>` so the trap-handler hook
    /// can read without panicking on a poisoned lock, and the
    /// kernel-stack body can swap in a fresh waker per entry.
    current_waker: narf_lib::sync::IrqSafeSpinLock<Option<Waker>>,
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
            current_waker: narf_lib::sync::IrqSafeSpinLock::new(None),
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
        waker: &Waker,
    ) -> Poll<()> {
        // Stash the executor's waker so the inner future's
        // `cx.waker().wake_by_ref()` (e.g. from `yield_now()`)
        // re-arms the correct slot — see `task_body_rust`.
        *self.current_waker.lock() = Some(waker.clone());
        // Publish exec_ctx so the task can find it on yield.
        self.exec_ctx
            .store(exec_ctx as *mut _, Ordering::Release);
        // Record when this slice started — the trap-handler
        // preempt hook reads `tsc_started` to decide whether
        // we've used our slice.
        self.tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
        // CURRENT_STACKFUL_TASK is managed by task_body_rust
        // (set at top of each poll iter, cleared before yield).
        // The executor side touching it would open a race window
        // between switch-back-from-task and the clear, during
        // which a timer tick could mistakenly preempt the
        // already-yielded task and overwrite its ctx.
        // SAFETY: ctx + exec_ctx both live for the duration of
        // this call; the task's stack was allocated by us and is
        // still alive; the trampoline_entry symbol is in this
        // crate's code segment.
        unsafe { kernel_switch(exec_ctx as *mut _, &self.ctx) };
        // ── We are resumed here when the task yields back ──
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
    let task_ptr: *mut KernelTask = task as *mut _;

    loop {
        // Take ownership of CURRENT_STACKFUL_TASK on whatever
        // CPU we're on. This is the ONLY place CURRENT gets
        // set — by the task itself, while it's actually
        // executing — so try_preempt's view of "who's running"
        // is precise: between the .store(self) below and the
        // .store(null) before kernel_switch, the task is on
        // this CPU and preemptable. Outside that window
        // CURRENT[cpu] is null and try_preempt no-ops.
        let cpu = this_cpu();
        CURRENT_STACKFUL_TASK.inner[cpu].store(task_ptr, Ordering::Release);

        let prev_52 = STACKFUL_POLL_TICKS.fetch_add(1, Ordering::Relaxed);
        narf_memory::beacon::paint(
            52,
            if prev_52 & 1 == 0 { 0x00FF_FFFF } else { 0x0080_80FF },
        );
        let waker_guard = task.current_waker.lock();
        let waker = match waker_guard.as_ref() {
            Some(w) => w.clone(),
            None => KernelTask::no_op_waker(),
        };
        drop(waker_guard);
        let mut cx = Context::from_waker(&waker);
        let result = task.future.as_mut().poll(&mut cx);
        let prev_53 = STACKFUL_YIELD_TICKS.fetch_add(1, Ordering::Relaxed);
        narf_memory::beacon::paint(
            53,
            if prev_53 & 1 == 0 { 0x0000_FF80 } else { 0x00FF_8000 },
        );
        match result {
            Poll::Ready(()) => {
                task.completed.store(true, Ordering::Release);
                // Fall through and yield one last time — the
                // executor checks `completed` after we yield and
                // drops the slot.
            }
            Poll::Pending => {}
        }
        // Clear CURRENT_STACKFUL_TASK before yielding so a
        // timer tick landing between this clear and the
        // kernel_switch below (or while we're switched out)
        // doesn't preempt a task that's no longer executing.
        // Re-read cpu in case the task migrated mid-poll.
        let cpu = this_cpu();
        CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);
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

/// Inspect a trap frame at LAPIC timer entry; if a stackful task
/// is currently CPU-bound and has used its slice, yield to the
/// executor right here from inside the trap handler.
///
/// Design (replaces the earlier IRET-rewrite stub approach):
///
/// 1. The task is mid-execution when the timer fires.
/// 2. CPU pushes a trap frame onto the task's own kernel stack.
/// 3. common_trap pushes GPRs + calls rust_trap_handler.
/// 4. rust_trap_handler calls `try_preempt` (this fn).
/// 5. We arm the executor's slot waker (so the slot gets re-
///    polled), then call `kernel_switch(&mut task.ctx, exec_ctx)`.
///    The save half stores trap_handler's current state into
///    task.ctx — INCLUDING the IF=0 state (long-mode interrupt
///    gate cleared IF on trap entry).
/// 6. Control transfers to the executor's continuation. The
///    executor runs other tasks (init, shell, peer pumps).
/// 7. Eventually the executor (or any caller) does
///    `kernel_switch(?, &task.ctx)` to come back. The load half
///    restores trap_handler's rsp/rip/IF=0 state — we resume
///    right here, inside `try_preempt`, with IF=0.
/// 8. We return to trap_handler. common_trap pops GPRs from the
///    UNTOUCHED trap frame on the task's stack, runs `add rsp,
///    16` and `iretq`, restoring the task's pre-trap rsp/rip/
///    rflags. Task runs again at the instruction that was
///    interrupted.
///
/// No frame rewrite, no synthetic stub, no lossy-stack reset.
/// The trap frame's the persistence mechanism; kernel_switch is
/// the yield mechanism. They cooperate naturally.
///
/// # Safety
/// - Must be called from within `rust_trap_handler` with the
///   actual on-stack TrapFrame. Caller passes `&mut TrapFrame`
///   that's part of the trap.S-pushed frame.
/// - `narf-frame`'s TrapFrame layout must match scheduler's
///   `TrapFrame` declared above — there's a const-assert in
///   `narf-frame` that enforces this.
/// - Caller must have done EOI BEFORE calling this — once we
///   yield to the executor, no more IRQs from this vector can
///   fire until the LAPIC's in-service bit clears.
#[cfg(target_arch = "x86_64")]
pub unsafe fn try_preempt(frame: &mut TrapFrame) -> bool {
    if frame.vector != PREEMPT_VECTOR {
        return false;
    }
    if !cpl_zero(frame.cs) {
        return false; // trapped from user mode; not our path
    }
    let cpu = this_cpu();
    let task_ptr = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if task_ptr.is_null() {
        return false; // no stackful task currently polling on this CPU
    }
    // SAFETY: CURRENT_STACKFUL_TASK is only set by an in-progress
    // `poll_to_yield` whose caller still holds the Box alive; the
    // pointer remains valid until poll_to_yield clears it.
    let no_preempt = unsafe { (*task_ptr).no_preempt.load(Ordering::Acquire) };
    if no_preempt {
        return false;
    }
    let started = unsafe { (*task_ptr).tsc_started.load(Ordering::Acquire) };
    let slice = unsafe { (*task_ptr).slice_cycles.load(Ordering::Acquire) };
    let now = narf_time::now_cycles();
    if now.saturating_sub(started) < slice {
        return false; // task hasn't used its slice yet
    }
    let exec_ctx = unsafe { (*task_ptr).exec_ctx.load(Ordering::Acquire) };
    if exec_ctx.is_null() {
        return false; // no executor to switch to
    }

    // Arm the executor's slot waker so we get re-polled when the
    // executor runs out of other ready tasks. Without this, the
    // slot's `awake` flag stays at the false the last poll
    // cleared it to, and we'd be dormant forever (the inner
    // future never finished, so it never called wake_by_ref).
    unsafe {
        let waker_guard = (*task_ptr).current_waker.lock();
        if let Some(w) = waker_guard.as_ref() {
            w.wake_by_ref();
        }
        drop(waker_guard);
    }

    // Mark for debug visibility (consumed by the smoke tests).
    unsafe {
        core::ptr::write_volatile((*task_ptr).saved_trap_frame.get(), *frame);
        (*task_ptr).preempted.store(true, Ordering::Release);
    }

    // Clear CURRENT so timer ticks during the switch-out window
    // don't try to preempt a task that's no longer executing on
    // this CPU. task_body_rust re-publishes CURRENT at the top
    // of its next poll iter.
    CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);

    // Save trap_handler's continuation into task.ctx; switch to
    // executor. The kernel_switch save half stores rbx/rbp/r12-r15,
    // rsp+8 (post-call rsp), the return PC (next instruction
    // after the kernel_switch call), AND current RFLAGS (which
    // includes IF=0 since we're in a trap handler).
    let task_ctx_ptr = unsafe { &raw mut (*task_ptr).ctx };
    unsafe { kernel_switch(task_ctx_ptr, exec_ctx) };

    // ── Resumed here when the executor switches back into this
    //    task. Re-publish CURRENT for whichever CPU we now run
    //    on (SMP may have migrated us between yields) and
    //    restart the slice counter so we're measured from now.
    //
    // Critical: we re-publish in the preempt-resume path
    // because the iretq below will return to the task's
    // pre-trap RIP — NOT to task_body_rust's loop top. So
    // task_body_rust's CURRENT.store(self) at the next iter
    // won't run until the task cooperatively yields. Without
    // re-publishing here, subsequent timer ticks see
    // CURRENT=null and never preempt — the task busy-loop runs
    // forever until it yields on its own.
    let cpu = this_cpu();
    unsafe {
        CURRENT_STACKFUL_TASK.inner[cpu].store(task_ptr, Ordering::Release);
        (*task_ptr)
            .tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
    }
    true
}

/// Counter for slot-52 beacon (pre-inner-poll heartbeat).
/// Surfaced via toggling colour at task_body_rust each round.
static STACKFUL_POLL_TICKS: AtomicU64 = AtomicU64::new(0);
/// Counter for slot-53 beacon (post-inner-poll / pre-yield).
/// Surfaced via toggling colour after the inner future polls.
static STACKFUL_YIELD_TICKS: AtomicU64 = AtomicU64::new(0);

// The earlier preempt_yield_stub + preempt_yield_stub_body +
// PENDING_YIELD_TASK design (IRET-rewrite) has been retired —
// see `try_preempt` above. The new design switches directly from
// inside the trap handler via kernel_switch, relying on the
// existing trap-handler return path (common_trap pops GPRs +
// iretq) to resume the task at its pre-trap RIP when the
// executor switches back in. No frame rewrite, no synthetic
// stub, no lossy-stack reset.

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
        //
        // Pass `cx.waker()` into poll_to_yield. It plumbs through
        // KernelTask::current_waker → the Context that
        // task_body_rust uses to poll the inner future. That
        // way, when the inner future does `yield_now().await`
        // (which calls cx.waker().wake_by_ref() before returning
        // Pending), the executor's slot.awake flag flips and we
        // get re-polled next round. NO unconditional re-arm
        // here — only re-arm if the inner future asks for it,
        // otherwise busy-looping pumps would starve everyone else.
        #[cfg(target_arch = "x86_64")]
        {
            let this = unsafe { self.get_unchecked_mut() };
            let mut exec_ctx = KernelContext::default();
            // SAFETY: single-threaded; this poll() is the only
            // active caller of this KernelTask.
            unsafe { this.inner.poll_to_yield(&mut exec_ctx, cx.waker()) }
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
        let waker = KernelTask::no_op_waker();
        // SAFETY: single-threaded test; no preemption.
        let result = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
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
        let waker = KernelTask::no_op_waker();
        // First three polls should be Pending, fourth Ready.
        for expected_count in 1..=3 {
            // SAFETY: same.
            let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
            if r != Poll::Pending {
                return TestResult::Fail("expected Pending while counter < 4");
            }
            if COUNTER.load(Ordering::Acquire) != expected_count {
                return TestResult::Fail("counter mismatch on Pending iteration");
            }
        }
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready after countdown");
        }
        if COUNTER.load(Ordering::Acquire) != 4 {
            return TestResult::Fail("final counter wrong");
        }
        TestResult::Pass
    }

    // ── try_preempt filter coverage ─────────────────────────────────
    //
    // Build a synthetic trap-frame on the test's stack with the
    // various combinations of (vector, cs, no_preempt, slice
    // elapsed) and verify try_preempt's return matches the rules.
    // None of these should ever reach the kernel_switch — they
    // should ALL early-return false. (Real switching is exercised
    // by the round-trip test below.)

    #[cfg(target_arch = "x86_64")]
    fn zero_trap_frame() -> TrapFrame {
        zeroed_trap_frame()
    }

    /// Wrong vector → no preempt. try_preempt is gated on vector
    /// 32 (LAPIC timer) only; other IRQs and exceptions don't
    /// trigger the slice check.
    #[cfg(target_arch = "x86_64")]
    fn smoke_try_preempt_skips_non_preempt_vector() -> TestResult {
        let mut frame = zero_trap_frame();
        frame.vector = 33; // anything other than 32
        frame.cs = 0x08;   // CPL=0
        // Doesn't matter what CURRENT_STACKFUL_TASK holds — the
        // vector check fires first.
        let result = unsafe { try_preempt(&mut frame) };
        if result {
            return TestResult::Fail("preempted on vector != 32");
        }
        TestResult::Pass
    }

    /// User-mode trap (CPL=3) → no preempt. User-task preemption
    /// is the executor's job, not the stackful hook's.
    #[cfg(target_arch = "x86_64")]
    fn smoke_try_preempt_skips_user_mode() -> TestResult {
        let mut frame = zero_trap_frame();
        frame.vector = PREEMPT_VECTOR;
        frame.cs = 0x1b; // user CS (RPL=3)
        let result = unsafe { try_preempt(&mut frame) };
        if result {
            return TestResult::Fail("preempted a CPL=3 trap");
        }
        TestResult::Pass
    }

    /// No stackful task on this CPU → no preempt. CURRENT_STACKFUL_TASK
    /// starts null; verify the early-return is taken cleanly.
    #[cfg(target_arch = "x86_64")]
    fn smoke_try_preempt_skips_when_no_task() -> TestResult {
        let cpu = this_cpu();
        // Belt + braces: explicitly null. Other tests may have
        // left state behind on the same CPU's slot.
        CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);
        let mut frame = zero_trap_frame();
        frame.vector = PREEMPT_VECTOR;
        frame.cs = 0x08;
        let result = unsafe { try_preempt(&mut frame) };
        if result {
            return TestResult::Fail("preempted with no current task");
        }
        TestResult::Pass
    }

    /// Slice not expired → no preempt. Set tsc_started=now and
    /// slice_cycles huge; try_preempt should observe insufficient
    /// elapsed time and return false WITHOUT touching the wheel
    /// or doing a kernel_switch.
    #[cfg(target_arch = "x86_64")]
    fn smoke_try_preempt_respects_slice_budget() -> TestResult {
        // Build a fresh task. We only inspect the early-return path
        // — we don't actually let try_preempt go past the budget
        // check (the kernel_switch later would invalidate the test's
        // assumption that try_preempt returns to it).
        struct Forever;
        impl Future for Forever {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        let task = KernelTask::new(Forever);
        let task_ptr = &*task as *const KernelTask as *mut KernelTask;
        task.tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
        task.slice_cycles.store(u64::MAX / 2, Ordering::Release);
        let cpu = this_cpu();
        CURRENT_STACKFUL_TASK.inner[cpu].store(task_ptr, Ordering::Release);

        let mut frame = zero_trap_frame();
        frame.vector = PREEMPT_VECTOR;
        frame.cs = 0x08;
        let result = unsafe { try_preempt(&mut frame) };

        // Clean up before checking — keep the global pristine.
        CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);

        if result {
            return TestResult::Fail("preempted before slice expired");
        }
        TestResult::Pass
    }

    /// no_preempt opt-out → never preempt. Drivers holding HW
    /// locks across a critical section can set this to keep the
    /// timer from yanking the CPU away.
    #[cfg(target_arch = "x86_64")]
    fn smoke_try_preempt_respects_no_preempt_flag() -> TestResult {
        struct Forever;
        impl Future for Forever {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        let task = KernelTask::new(Forever);
        let task_ptr = &*task as *const KernelTask as *mut KernelTask;
        task.no_preempt.store(true, Ordering::Release);
        // Slice WOULD be expired (started ago, slice tiny) — only
        // the no_preempt flag should save us.
        task.tsc_started.store(0, Ordering::Release);
        task.slice_cycles.store(1, Ordering::Release);
        let cpu = this_cpu();
        CURRENT_STACKFUL_TASK.inner[cpu].store(task_ptr, Ordering::Release);

        let mut frame = zero_trap_frame();
        frame.vector = PREEMPT_VECTOR;
        frame.cs = 0x08;
        let result = unsafe { try_preempt(&mut frame) };

        CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);

        if result {
            return TestResult::Fail("preempted despite no_preempt=true");
        }
        TestResult::Pass
    }

    /// A future that keeps Pending indefinitely until a static
    /// flag flips. Used to model a CPU-bound task that needs
    /// preemption to yield control.
    struct WaitOnFlag {
        flag: &'static AtomicBool,
        polls: &'static AtomicU32,
    }
    impl Future for WaitOnFlag {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            if self.flag.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    /// poll_to_yield round-trip preserves task state across yields.
    /// Polls Pending, switches back to executor, polls again, and
    /// confirms the future's internal counter advanced — i.e., the
    /// stackful task's state survived the round trip and reached
    /// the inner future on each entry.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_pending_round_trips_preserve_state() -> TestResult {
        static FLAG: AtomicBool = AtomicBool::new(false);
        static POLLS: AtomicU32 = AtomicU32::new(0);
        FLAG.store(false, Ordering::Release);
        POLLS.store(0, Ordering::Release);

        let mut task = KernelTask::new(WaitOnFlag {
            flag: &FLAG,
            polls: &POLLS,
        });
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();

        // Poll N times: should always be Pending, and counter
        // advances one per poll.
        for expected in 1..=8 {
            let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
            if r != Poll::Pending {
                return TestResult::Fail("expected Pending while flag false");
            }
            if POLLS.load(Ordering::Acquire) != expected {
                return TestResult::Fail("inner future not entered on every round-trip");
            }
        }

        // Flip the flag; next poll should return Ready.
        FLAG.store(true, Ordering::Release);
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready after flag set");
        }
        TestResult::Pass
    }

    /// Verify a stackful task's stack pointer is on its OWN
    /// allocated stack, not the executor's. Catches a regression
    /// where someone might "optimize" by sharing the executor stack.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_runs_on_dedicated_stack() -> TestResult {
        use core::sync::atomic::AtomicU64;
        static TASK_RSP: AtomicU64 = AtomicU64::new(0);
        static TASK_STACK_BASE: AtomicU64 = AtomicU64::new(0);
        static TASK_STACK_TOP: AtomicU64 = AtomicU64::new(0);

        struct CaptureRsp;
        impl Future for CaptureRsp {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                let rsp: u64;
                unsafe {
                    core::arch::asm!("mov {0}, rsp", out(reg) rsp,
                        options(nomem, nostack, preserves_flags));
                }
                TASK_RSP.store(rsp, Ordering::Release);
                Poll::Ready(())
            }
        }
        TASK_RSP.store(0, Ordering::Release);

        let task = KernelTask::new(CaptureRsp);
        // Snapshot expected stack range from the box.
        let base = task.stack.as_ptr() as u64;
        let top = base + task.stack.len() as u64;
        TASK_STACK_BASE.store(base, Ordering::Release);
        TASK_STACK_TOP.store(top, Ordering::Release);
        let mut task = task;
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready");
        }

        let observed_rsp = TASK_RSP.load(Ordering::Acquire);
        let base = TASK_STACK_BASE.load(Ordering::Acquire);
        let top = TASK_STACK_TOP.load(Ordering::Acquire);
        if observed_rsp < base || observed_rsp > top {
            return TestResult::Fail("task rsp wasn't on the allocated stack");
        }
        TestResult::Pass
    }

    /// Multiple stackful tasks can be created and polled
    /// independently in sequence, each on its own stack. Catches
    /// state-bleed bugs between distinct KernelTask instances.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_multiple_independent_tasks() -> TestResult {
        static COUNTER_A: AtomicU32 = AtomicU32::new(0);
        static COUNTER_B: AtomicU32 = AtomicU32::new(0);
        COUNTER_A.store(0, Ordering::Release);
        COUNTER_B.store(0, Ordering::Release);

        let mut task_a = KernelTask::new(TrivialFuture { counter: &COUNTER_A });
        let mut task_b = KernelTask::new(TrivialFuture { counter: &COUNTER_B });
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();

        // Interleaved polls — each task uses its own ctx + stack.
        let ra = unsafe { task_a.poll_to_yield(&mut exec_ctx, &waker) };
        let rb = unsafe { task_b.poll_to_yield(&mut exec_ctx, &waker) };
        if ra != Poll::Ready(()) || rb != Poll::Ready(()) {
            return TestResult::Fail("one of the tasks didn't complete");
        }
        if COUNTER_A.load(Ordering::Acquire) != 1
            || COUNTER_B.load(Ordering::Acquire) != 1
        {
            return TestResult::Fail("counters bled between tasks");
        }
        TestResult::Pass
    }

    /// Stack pointers of two concurrently-instantiated stackful
    /// tasks are distinct (different allocations). Pre-empt
    /// machinery is per-task and would corrupt state if two tasks
    /// shared a stack.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_distinct_stacks_across_tasks() -> TestResult {
        struct NoopReady;
        impl Future for NoopReady {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        let a = KernelTask::new(NoopReady);
        let b = KernelTask::new(NoopReady);
        let a_base = a.stack.as_ptr() as usize;
        let a_top = a_base + a.stack.len();
        let b_base = b.stack.as_ptr() as usize;
        let b_top = b_base + b.stack.len();

        // Disjoint ranges.
        if a_top > b_base && a_base < b_top {
            return TestResult::Fail("stacks overlap between tasks");
        }
        TestResult::Pass
    }

    /// `set_no_preempt` flips the flag the trap-handler hook
    /// reads. Visible via the public observation of the task's
    /// own state.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_no_preempt_setter_round_trips() -> TestResult {
        struct NoopPending;
        impl Future for NoopPending {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        let task = KernelTask::new(NoopPending);
        if task.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("no_preempt should default false");
        }
        task.set_no_preempt(true);
        if !task.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("set_no_preempt(true) didn't stick");
        }
        task.set_no_preempt(false);
        if task.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("set_no_preempt(false) didn't stick");
        }
        TestResult::Pass
    }

    /// `set_slice_cycles` mutates the per-task slice budget.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_slice_cycles_setter_round_trips() -> TestResult {
        struct NoopPending;
        impl Future for NoopPending {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        let task = KernelTask::new(NoopPending);
        if task.slice_cycles.load(Ordering::Acquire) != DEFAULT_SLICE_CYCLES {
            return TestResult::Fail("default slice mismatch");
        }
        task.set_slice_cycles(123_456);
        if task.slice_cycles.load(Ordering::Acquire) != 123_456 {
            return TestResult::Fail("set_slice_cycles didn't stick");
        }
        TestResult::Pass
    }

    /// The executor-supplied waker is plumbed into the inner
    /// future's Context. yield-style futures that call
    /// `cx.waker().wake_by_ref()` need this — without it they
    /// silently drop wakes onto the no-op fallback.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_inner_waker_is_executor_waker() -> TestResult {
        use alloc::sync::Arc;
        use alloc::task::Wake;
        use core::task::Waker;
        static OBSERVED_WAKER_DATA: AtomicU64 = AtomicU64::new(0);

        struct CountingWaker {
            wakes: AtomicU32,
        }
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::AcqRel);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::AcqRel);
            }
        }

        struct CaptureWakerData;
        impl Future for CaptureWakerData {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                // We can't directly inspect the inner Waker's data
                // ptr, but we CAN call wake_by_ref on it. If the
                // executor-supplied waker plumbed through, our
                // wake counter advances.
                cx.waker().wake_by_ref();
                Poll::Ready(())
            }
        }

        let observer = Arc::new(CountingWaker {
            wakes: AtomicU32::new(0),
        });
        let waker: Waker = observer.clone().into();
        // SAFETY: u64 cast of the Arc data ptr is a stable diagnostic.
        OBSERVED_WAKER_DATA.store(
            Arc::as_ptr(&observer) as u64,
            Ordering::Release,
        );

        let mut task = KernelTask::new(CaptureWakerData);
        let mut exec_ctx = KernelContext::default();
        let _ = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };

        if observer.wakes.load(Ordering::Acquire) == 0 {
            return TestResult::Fail("inner future's waker didn't reach the executor's waker");
        }
        TestResult::Pass
    }

    /// StackfulAdapter::with_options applies slice + no_preempt
    /// + stack size to the inner KernelTask.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_adapter_applies_options() -> TestResult {
        struct NoopPending;
        impl Future for NoopPending {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        let opts = crate::StackfulOptions {
            slice_cycles: 42_000_000,
            no_preempt: true,
            stack_bytes: 32 * 1024,
        };
        let adapter = StackfulAdapter::with_options(NoopPending, opts);
        if adapter.inner.slice_cycles.load(Ordering::Acquire) != 42_000_000 {
            return TestResult::Fail("slice_cycles not applied");
        }
        if !adapter.inner.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("no_preempt not applied");
        }
        if adapter.inner.stack.len() != 32 * 1024 {
            return TestResult::Fail("stack_bytes not applied");
        }
        TestResult::Pass
    }

    /// StackfulOptions::default matches the publicly-documented
    /// defaults. Drivers spawning with `..Default::default()`
    /// need this contract.
    fn smoke_stackful_options_defaults_match_constants() -> TestResult {
        let opts = crate::StackfulOptions::default();
        if opts.slice_cycles != DEFAULT_SLICE_CYCLES {
            return TestResult::Fail("default slice_cycles drifted");
        }
        if opts.no_preempt {
            return TestResult::Fail("default no_preempt should be false");
        }
        if opts.stack_bytes != DEFAULT_KERNEL_STACK_BYTES {
            return TestResult::Fail("default stack_bytes drifted");
        }
        TestResult::Pass
    }

    /// KernelTask::with_stack_size honours the requested size and
    /// allocates a 16-byte-aligned stack.
    #[cfg(target_arch = "x86_64")]
    fn smoke_kernel_task_stack_size_round_trips() -> TestResult {
        struct NoopPending;
        impl Future for NoopPending {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        for &size in &[4096usize, 16 * 1024, 32 * 1024, 64 * 1024] {
            let task = KernelTask::with_stack_size(NoopPending, size);
            if task.stack.len() != size {
                return TestResult::Fail("stack length mismatch");
            }
            if (task.stack.as_ptr() as usize) & 0xF != 0 {
                return TestResult::Fail("stack base not 16-aligned");
            }
        }
        TestResult::Pass
    }

    /// `yield_now()` returns Pending + self-wake on first poll,
    /// then Ready on the second. Core cooperative-yield primitive
    /// every async driver depends on.
    #[cfg(target_arch = "x86_64")]
    fn smoke_yield_now_pending_then_ready() -> TestResult {
        use alloc::sync::Arc;
        use alloc::task::Wake;
        use core::task::Waker;

        struct CountingWaker {
            wakes: AtomicU32,
        }
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::AcqRel);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::AcqRel);
            }
        }

        let observer = Arc::new(CountingWaker {
            wakes: AtomicU32::new(0),
        });
        let waker: Waker = observer.clone().into();
        let mut cx = Context::from_waker(&waker);

        let mut y = crate::yield_now();
        let r1 = Pin::new(&mut y).poll(&mut cx);
        if r1 != Poll::Pending {
            return TestResult::Fail("first poll of yield_now should be Pending");
        }
        if observer.wakes.load(Ordering::Acquire) == 0 {
            return TestResult::Fail("yield_now didn't re-arm its waker on first poll");
        }
        let r2 = Pin::new(&mut y).poll(&mut cx);
        if r2 != Poll::Ready(()) {
            return TestResult::Fail("second poll of yield_now should be Ready");
        }
        TestResult::Pass
    }

    /// Multi-task concurrency through the cooperative executor:
    /// spawn N stackful tasks each counting up to M; pump
    /// poll_one_round repeatedly; verify every task hits its
    /// target without lost updates or cross-task interference.
    /// Exercises the full path: spawn_stackful → executor queue
    /// → StackfulAdapter::poll → poll_to_yield → kernel_switch
    /// → task_body_rust → inner future → yield_now → switch back.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_multi_stackful_via_executor() -> TestResult {
        const TASKS: usize = 4;
        const TARGET: u32 = 5;
        static COUNTERS: [AtomicU32; TASKS] = [
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ];
        for c in COUNTERS.iter() {
            c.store(0, Ordering::Release);
        }

        struct Counter {
            idx: usize,
            target: u32,
            seen: u32,
        }
        impl Future for Counter {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.seen >= self.target {
                    return Poll::Ready(());
                }
                COUNTERS[self.idx].fetch_add(1, Ordering::AcqRel);
                self.seen += 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..TASKS {
            crate::spawn_stackful(Counter {
                idx: i,
                target: TARGET,
                seen: 0,
            });
        }

        // Drive the executor enough rounds that every counter
        // reaches its target. With TASKS=4 and TARGET=5, 4*5=20
        // poll-completions needed. poll_one_round walks every
        // ready slot once. 64 rounds is plenty of headroom even
        // if other boot tasks share the queue.
        for _ in 0..64 {
            crate::poll_one_round();
            if COUNTERS.iter().all(|c| c.load(Ordering::Acquire) >= TARGET) {
                break;
            }
        }

        for (i, c) in COUNTERS.iter().enumerate() {
            let v = c.load(Ordering::Acquire);
            if v != TARGET {
                let _ = i;
                let _ = v;
                return TestResult::Fail(
                    "one of the concurrent stackful tasks didn't reach its target",
                );
            }
        }
        TestResult::Pass
    }

    /// Concurrency without preempt (no_preempt=true on every
    /// task): tasks still round-robin via the cooperative yield
    /// path (`yield_now().await`). Validates that the wake re-
    /// arms the executor slot for tasks that opt out of timer
    /// preemption.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_no_preempt_still_round_robins() -> TestResult {
        static A: AtomicU32 = AtomicU32::new(0);
        static B: AtomicU32 = AtomicU32::new(0);
        A.store(0, Ordering::Release);
        B.store(0, Ordering::Release);

        struct YieldCount {
            counter: &'static AtomicU32,
            remaining: u32,
        }
        impl Future for YieldCount {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                self.counter.fetch_add(1, Ordering::AcqRel);
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        let opts = crate::StackfulOptions {
            no_preempt: true,
            ..Default::default()
        };
        crate::spawn_stackful_with_options(
            YieldCount {
                counter: &A,
                remaining: 3,
            },
            opts,
        );
        crate::spawn_stackful_with_options(
            YieldCount {
                counter: &B,
                remaining: 3,
            },
            opts,
        );

        for _ in 0..32 {
            crate::poll_one_round();
            if A.load(Ordering::Acquire) >= 3 && B.load(Ordering::Acquire) >= 3 {
                break;
            }
        }
        if A.load(Ordering::Acquire) != 3 || B.load(Ordering::Acquire) != 3 {
            return TestResult::Fail(
                "no_preempt tasks didn't round-robin to completion via cooperative yield",
            );
        }
        TestResult::Pass
    }

    /// task_body_rust manages CURRENT_STACKFUL_TASK directly: it
    /// sets the slot at the top of each poll iter and clears it
    /// before yielding. Verify that after a Ready return the slot
    /// is null on this CPU.
    #[cfg(target_arch = "x86_64")]
    fn smoke_current_task_cleared_after_poll() -> TestResult {
        struct ReadyImmediately;
        impl Future for ReadyImmediately {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        let cpu = this_cpu();
        CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);

        let mut task = KernelTask::new(ReadyImmediately);
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        let _ = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };

        let after = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
        if !after.is_null() {
            return TestResult::Fail(
                "CURRENT_STACKFUL_TASK not cleared on this CPU after Ready return",
            );
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
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_try_preempt_skips_non_preempt_vector
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_try_preempt_skips_user_mode);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_try_preempt_skips_when_no_task
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_try_preempt_respects_slice_budget
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_try_preempt_respects_no_preempt_flag
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_pending_round_trips_preserve_state
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_runs_on_dedicated_stack
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_multiple_independent_tasks
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_distinct_stacks_across_tasks
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_no_preempt_setter_round_trips
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_slice_cycles_setter_round_trips
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_inner_waker_is_executor_waker
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_current_task_cleared_after_poll
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_adapter_applies_options
    );
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_options_defaults_match_constants
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_kernel_task_stack_size_round_trips
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_yield_now_pending_then_ready);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_multi_stackful_via_executor
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_no_preempt_still_round_robins
    );
}
