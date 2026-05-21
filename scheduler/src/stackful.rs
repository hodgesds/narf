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
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use core::task::{Context, Poll, Waker};

#[cfg(target_arch = "x86_64")]
use narf_arch::x86_64::kernel_ctx::{kernel_switch, KernelContext};

/// Default per-task kernel stack size. 16 KiB matches the TSS.rsp0
/// stack the kernel uses for user→kernel trap entry; deep enough
/// for any in-kernel future poll path that doesn't do unbounded
/// recursion.
pub const DEFAULT_KERNEL_STACK_BYTES: usize = 16 * 1024;

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
}

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
        // SAFETY: ctx + exec_ctx both live for the duration of
        // this call; the task's stack was allocated by us and is
        // still alive; the trampoline_entry symbol is in this
        // crate's code segment.
        unsafe { kernel_switch(exec_ctx as *mut _, &self.ctx) };
        // ── We are resumed here when the task yields back ──
        // exec_ctx was used for state — clear the pointer so a
        // stray late switch can't write into a stale local.
        self.exec_ctx.store(core::ptr::null_mut(), Ordering::Release);
        if self.completed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
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
}

impl Future for StackfulAdapter {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
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
            unsafe { this.inner.poll_to_yield(&mut exec_ctx) }
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
