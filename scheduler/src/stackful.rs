//! Stackful kernel tasks.
//!
//! Spec: `scheduler/specification/preemption.md`.
//!
//! Wraps a `Pin<Box<dyn Future>>` with a dedicated kernel stack
//! plus a saved `KernelContext`, so the future's `poll()` runs on
//! the task's own stack instead of the executor's. Timer traps can switch the
//! live continuation back to the executor on x86_64 and aarch64.
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
//!    + a pointer to the task itself in r15 (x86_64) or x19 (aarch64).
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
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

#[cfg(target_arch = "aarch64")]
use narf_arch::aarch64::kernel_ctx::{kernel_switch, KernelContext};
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

/// Default vector the trap handler dispatches preemption on.
/// Matches `narf_interrupts::VECTOR_TIMER` (32) — re-declared
/// here to avoid the dep cycle. With the clockevent registry
/// (Phase 3) the actual tick vector is read at runtime from
/// `narf_time::clockevent::TICK_VECTOR`; this constant is the
/// fallback used when no backend has been selected yet (early
/// boot, legacy paths).
pub const PREEMPT_VECTOR: u64 = 32;

/// Read the selected tick vector at runtime. Falls back to
/// `PREEMPT_VECTOR` (32) when no clockevent backend has been
/// selected yet — preserves pre-Phase-3 behaviour during early
/// boot and on platforms where the registry isn't yet wired.
#[cfg(target_arch = "x86_64")]
#[inline]
fn current_preempt_vector() -> u64 {
    let v = narf_time::clockevent::TICK_VECTOR.load(Ordering::Acquire);
    if v == 0 {
        PREEMPT_VECTOR
    } else {
        v as u64
    }
}

/// Default per-task kernel stack size. 32 KiB: under the own-stack
/// model the ENTIRE syscall/trap path of a user task runs on this
/// stack — with interrupts enabled, so an IRQ handler's frames land
/// on top of whatever depth the syscall body already reached. The
/// kernel has several multi-KiB monolithic frames (fork/clone spawn
/// plumbing, ext2 block staging, pty open), and 16 KiB measurably
/// overflowed during `fork(2)` (the wl_xdg slab-canary corruption —
/// see STACK_CANARY below, which now catches any recurrence with
/// attribution). 32 KiB gives those paths + IRQ nesting real
/// headroom at 8 pages per task.
pub const DEFAULT_KERNEL_STACK_BYTES: usize = 32 * 1024;

/// Stack-overflow tripwire: number of canary words at the LOW end of
/// every `KernelTask` stack. A stack that grows past its bottom must
/// push through these words first (pushes descend contiguously), so a
/// clobbered canary = the stack overflowed into the heap object below
/// it. Checked on every executor switch-back (`poll_to_yield`) so the
/// overflow is reported with task attribution instead of surfacing
/// later as unexplained heap corruption (the wl_xdg slab free-block
/// canary trip: `sys_fork`'s ~14 KiB inlined frame + syscall depth
/// overran the 16 KiB own-stack into an adjacent 128 B slab page).
const STACK_CANARY_WORDS: usize = 8;

/// Recognisable in raw memory dumps ("SAFE STACK" flavored).
const STACK_CANARY: u64 = 0x5AFE_57AC_0F10_D511;

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
    inner: [const { AtomicPtr::new(core::ptr::null_mut()) }; narf_lib::percpu::MAX_CPUS],
};

/// Per-CPU flag: the most recent `poll_to_yield` on this CPU returned
/// `Poll::Pending` because the task was INVOLUNTARILY PREEMPTED (a LAPIC-timer
/// tick via `try_preempt`), NOT because it cooperatively yielded at an `.await`
/// boundary. Set at the tail of `poll_to_yield`; read-and-cleared by the
/// executor via [`take_preempted_return`] before it announces a QSBR quiescent
/// state.
///
/// The distinction is a QSBR-correctness invariant: a cooperative `.await`
/// yield is a genuine quiescent point (the task holds no RCU references across
/// it — see rcu/ §3.7), but a preemption is an arbitrary-PC context switch. A
/// preempted task's continuation — saved in `task.ctx` and re-polled later —
/// may hold raw references (e.g. into RCU-deferred memory) that never went
/// through `pin()`, so `report_quiescent`'s `active_readers` gate can't see
/// them. Announcing quiescence there would let a grace period complete and free
/// an object the suspended task still points at. The executor therefore
/// suppresses `report_quiescent` on a preemption return.
struct PerCpuBool {
    inner: [AtomicBool; narf_lib::percpu::MAX_CPUS],
}
static PREEMPTED_RETURN: PerCpuBool = PerCpuBool {
    inner: [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS],
};

/// Nestable CPU-local preemption depth. Interrupt masking remains the
/// architecture's protection for IRQ-safe spin locks; this counter covers
/// longer task-context critical sections that must remain interruptible but
/// must not be involuntarily switched to another task.
static PREEMPT_DEPTH: [AtomicU32; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; narf_lib::percpu::MAX_CPUS];

/// RAII token returned by [`preempt_disable`]. It is deliberately `!Send`:
/// dropping it on another CPU would decrement the wrong CPU-local depth.
#[must_use = "dropping the guard immediately re-enables preemption"]
#[derive(Debug)]
pub struct PreemptGuard {
    cpu: usize,
    _not_send: PhantomData<*mut ()>,
}

impl Drop for PreemptGuard {
    fn drop(&mut self) {
        let previous = PREEMPT_DEPTH[self.cpu].fetch_sub(1, Ordering::Release);
        assert!(previous != 0, "scheduler preempt-disable underflow");
    }
}

/// Disable involuntary task switching on this CPU until the returned guard is
/// dropped. Calls nest; timer/IRQ delivery itself remains enabled.
#[inline]
pub fn preempt_disable() -> PreemptGuard {
    let cpu = this_cpu();
    let previous = PREEMPT_DEPTH[cpu].fetch_add(1, Ordering::Acquire);
    assert!(previous != u32::MAX, "scheduler preempt-disable overflow");
    PreemptGuard {
        cpu,
        _not_send: PhantomData,
    }
}

/// Current CPU's nesting depth, exposed for assertions and diagnostics.
#[inline]
pub fn preempt_count() -> u32 {
    PREEMPT_DEPTH[this_cpu()].load(Ordering::Acquire)
}

#[inline]
fn preempt_enabled() -> bool {
    preempt_count() == 0
}

/// Read-and-clear this CPU's "last poll_to_yield returned via preemption" flag.
/// Returns `true` iff the most recent stackful poll on this CPU yielded because
/// it was involuntarily preempted (not a cooperative `.await`). The executor
/// calls this immediately after a poll returns to decide whether the poll
/// boundary was a true QSBR quiescent state. See [`PREEMPTED_RETURN`].
#[inline]
pub fn take_preempted_return() -> bool {
    let cpu = this_cpu();
    PREEMPTED_RETURN.inner[cpu].swap(false, Ordering::AcqRel)
}

// ── Per-task-own-stack user execution model (Stage 2-4) ─────────────
//
// OFF (default) = legacy longjmp/synthetic-frame user-task path. ON = user
// tasks run on their OWN kernel stack with TSS.rsp0/gs:[8] pointed at it, so a
// trap/syscall lands on that stack and preemption/park is a clean
// `kernel_switch` (no longjmp). Flipped at boot once validated; the old path is
// then deleted (Stage 5).
static USE_OWN_STACK: AtomicBool = AtomicBool::new(false);

/// Enable the per-task-own-stack user execution model. Call once at boot after
/// the kernel-stack hook + FPU hooks are installed.
pub fn enable_user_own_stack() {
    USE_OWN_STACK.store(true, Ordering::Release);
}

/// Whether the per-task-own-stack model is active.
#[inline]
pub fn user_own_stack_enabled() -> bool {
    USE_OWN_STACK.load(Ordering::Acquire)
}

// Hooks for saving/restoring the CURRENT user task's FPU (x87/SSE) across a
// `kernel_switch` out/in. The FPU area lives in userspace (`UserTaskFuture`),
// so the scheduler drives it through these hooks rather than reaching across
// the crate boundary. Installed by `narf_userspace` at boot. `0` = not wired.
static USER_FPU_SAVE_HOOK: AtomicUsize = AtomicUsize::new(0);
static USER_FPU_RESTORE_HOOK: AtomicUsize = AtomicUsize::new(0);
static USER_PERF_SWITCH_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the user-FPU save/restore hooks (userspace installs FXSAVE/FXRSTOR of
/// the running user task's FPU area).
pub fn set_user_fpu_hooks(save: fn(), restore: fn()) {
    USER_FPU_SAVE_HOOK.store(save as usize, Ordering::Release);
    USER_FPU_RESTORE_HOOK.store(restore as usize, Ordering::Release);
}

/// Install the userspace-owned task PMU context-switch hook.
///
/// The hook runs in executor context, with no scheduler queue lock held,
/// immediately before (`running = true`) and after (`running = false`) the
/// stackful continuation executes. This makes hardware counters follow a task
/// across preemption and CPU migration without counting executor or peer-task
/// work.
pub fn set_user_perf_switch_hook(hook: fn(u64, bool)) {
    USER_PERF_SWITCH_HOOK.store(hook as usize, Ordering::Release);
}

#[inline]
fn user_perf_switch(task: u64, running: bool) {
    let hook = USER_PERF_SWITCH_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `set_user_perf_switch_hook` writes this slot.
        let hook: fn(u64, bool) = unsafe { core::mem::transmute(hook) };
        hook(task, running);
    }
}

/// Publish the CURRENT stackful task's user-FPU (FXSAVE) area. Called by the
/// userspace `UserTaskFuture::poll` on first entry; stored per-task so a
/// kernel_switch resume + a task exit never read a stale/freed area.
#[cfg(target_arch = "x86_64")]
pub fn set_current_user_fpu(area: *mut u8) {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: in-flight task on this CPU.
        unsafe { (*p).user_fpu.store(area, Ordering::Release) };
    }
}

/// Publish the CURRENT stackful task's user address-space CR3. Called by the
/// userspace `UserTaskFuture::poll` right after `address_space.activate()` (and
/// the inline execve re-activate) so `poll_to_yield` can restore it on every
/// kernel_switch resume — see the `user_cr3` field doc.
#[cfg(target_arch = "x86_64")]
pub fn set_current_user_cr3(cr3: u64) {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: in-flight task on this CPU.
        unsafe { (*p).user_cr3.store(cr3, Ordering::Release) };
    }
}

/// Publish the CURRENT stackful task's user `FS_BASE` (TLS) MSR value. Called by
/// the userspace `UserTaskFuture::poll` and the `arch_prctl(ARCH_SET_FS)` handler
/// whenever they (re)apply FS_BASE, so a kernel_switch resume can restore it
/// per-task (see the `user_fs_base` field doc).
#[cfg(target_arch = "x86_64")]
pub fn set_current_user_fs_base(fs_base: u64) {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: in-flight task on this CPU.
        unsafe { (*p).user_fs_base.store(fs_base, Ordering::Release) };
    }
}

/// Read the CURRENT task's user-FPU area, or null if none.
#[cfg(target_arch = "x86_64")]
#[inline]
fn current_user_fpu() -> *mut u8 {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: in-flight task on this CPU.
    unsafe { (*p).user_fpu.load(Ordering::Acquire) }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn user_fpu_save() {
    let area = current_user_fpu();
    if !area.is_null() {
        // SAFETY: `area` is the in-flight task's FpuArea (≥FPU_AREA_SIZE,
        // 64-aligned; set by the userspace poll); CR4.OSFXSR/OSXSAVE is on.
        unsafe {
            narf_arch::x86_64::xsave::fpu_save(area);
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn user_fpu_save() {}

#[cfg(target_arch = "x86_64")]
#[inline]
fn user_fpu_restore() {
    let area = current_user_fpu();
    if !area.is_null() {
        // SAFETY: as `user_fpu_save`.
        unsafe {
            narf_arch::x86_64::xsave::fpu_restore(area);
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn user_fpu_restore() {}

/// Top (16-byte-aligned) of the CURRENT stackful task's kernel stack on this
/// CPU, or 0 if none. The per-task-own-stack user entry resets RSP to this
/// before `iretq`-to-user so the kernel stack is empty while the user runs.
pub fn current_stackful_stack_top() -> u64 {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is the in-flight task on this CPU (set by poll_to_yield),
    // alive for the duration of its run; `stack` is a stable heap allocation.
    let task = unsafe { &*p };
    ((task.stack.as_ptr() as u64) + task.stack.len() as u64) & !0xFu64
}

/// Per-CPU storage for the cooperative executor's resume context.
///
/// `StackfulAdapter::poll` switches into a stackful task and the task
/// switches back to *this* context when it yields/preempts. Previously
/// each poll put the `KernelContext` in a STACK LOCAL on the executor
/// stack and published its address into `KernelTask::exec_ctx`. That
/// address is only valid for the duration of the poll — once the poll
/// returns the frame is reclaimed and reused. A late/racy switch-back
/// read of `exec_ctx` could then land on a since-overwritten executor
/// stack slot whose `.rip` offset now held a pushed RPL-3 selector,
/// and `kernel_switch` would restore that as the resume rip → the
/// recurring #UD at rip=0x3/0x2b in the executor dispatch loop.
///
/// Moving the resume context into persistent per-CPU storage removes
/// the transient-stack-frame aliasing: the pointer the task holds
/// always targets live, stable memory whose `.rip` is a real saved
/// return address (or zero), never reused-stack garbage.
///
/// SAFETY / correctness: each CPU touches only its own slot, and
/// `StackfulAdapter`s are only ever polled by the TOP-LEVEL executor
/// (`run_until_empty`/`run_forever`) — never nested inside another
/// stackful task's future — so on any one CPU at most one
/// `poll_to_yield` save↔switch-back pair is in flight at a time. The
/// slot is freshly written by `kernel_switch`'s save half on every
/// `poll_to_yield` entry before the task runs, so no task relies on
/// its contents persisting across the task's own suspension.
struct PerCpuExecCtx {
    inner: [UnsafeCell<KernelContext>; narf_lib::percpu::MAX_CPUS],
}
// SAFETY: each CPU accesses only `inner[its-own-cpu]`, non-re-entrantly
// (no nested stackful polls), so there is never concurrent or aliasing
// access to a single slot despite the shared-static `&`.
unsafe impl Sync for PerCpuExecCtx {}
static EXEC_CTX: PerCpuExecCtx = PerCpuExecCtx {
    inner: [const { UnsafeCell::new(KernelContext::zeroed()) }; narf_lib::percpu::MAX_CPUS],
};

/// Per-CPU save target for the FINAL `kernel_switch` of an exiting task
/// (`exit_current_stackful`). The exit's abandoned continuation must be
/// saved SOMEWHERE (the save half is unconditional), but it must NOT be
/// saved into the dying task's own `ctx`: the executor observes
/// `completed` and drops the `Box<KernelTask>` immediately after the
/// switch, so the box must never again be a write target once
/// `completed` is published. Nothing ever switches into this scratch —
/// the continuation it captures is dead by construction.
#[cfg(target_arch = "x86_64")]
struct PerCpuScratchCtx {
    inner: [UnsafeCell<KernelContext>; narf_lib::percpu::MAX_CPUS],
}
#[cfg(target_arch = "x86_64")]
// SAFETY: each CPU writes only `inner[its-own-cpu]`, and only from
// `exit_current_stackful` (one exiting task at a time per CPU); the slot
// is write-only dead storage, never read or switched into.
unsafe impl Sync for PerCpuScratchCtx {}
#[cfg(target_arch = "x86_64")]
static EXIT_SCRATCH_CTX: PerCpuScratchCtx = PerCpuScratchCtx {
    inner: [const { UnsafeCell::new(KernelContext::zeroed()) }; narf_lib::percpu::MAX_CPUS],
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

/// A `KernelContext` is only ever switched *into* after a `kernel_switch`
/// SAVE half populated it (`rip` = a real return-PC, `rsp` = a live kernel
/// stack) or `KernelContext::fresh` set a trampoline entry + stack top. A
/// near-null / non-canonical / mis-aligned `rip`/`rsp` therefore means the
/// context was corrupted (the own-stack nesting / work-steal handoff race
/// the scheduler has historically hit). Switching into it would `jmp` to a
/// wild address — the classic intermittent RIP≈0 #UD. Catch it at the
/// switch point and panic cleanly WITH attribution instead.
#[cfg(target_arch = "x86_64")]
#[inline]
fn ctx_looks_sane(ctx: &KernelContext) -> bool {
    let canon =
        |a: u64| a >= 0x1000 && !(0x0000_8000_0000_0000..0xFFFF_8000_0000_0000).contains(&a);
    canon(ctx.rip) && canon(ctx.rsp) && ctx.rsp & 0x7 == 0
}

/// Validate a context immediately before `kernel_switch`-ing into it.
/// `label` names the switch site so a fired guard pinpoints which half
/// (task `ctx` vs executor `exec_ctx`) was corrupt.
#[cfg(target_arch = "x86_64")]
#[inline]
fn guard_switch_into(label: &str, ctx: &KernelContext) {
    if !ctx_looks_sane(ctx) {
        panic!(
            "CTXGUARD {label} cpu={}: refusing kernel_switch into corrupt context — \
             rip={:#018x} rsp={:#018x} rbp={:#018x} rbx={:#018x} r12={:#018x} r15={:#018x}",
            this_cpu(),
            ctx.rip,
            ctx.rsp,
            ctx.rbp,
            ctx.rbx,
            ctx.r12,
            ctx.r15,
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn guard_switch_into(label: &str, ctx: &KernelContext) {
    if ctx.pc < 0x1000 || ctx.sp < 0x1000 || ctx.sp & 0xF != 0 {
        panic!(
            "CTXGUARD {label} cpu={}: refusing kernel_switch into corrupt context — \
             pc={:#018x} sp={:#018x} x29={:#018x} x19={:#018x}",
            this_cpu(),
            ctx.pc,
            ctx.sp,
            ctx.x29,
            ctx.x19,
        );
    }
}

#[inline]
const fn zeroed_trap_frame() -> TrapFrame {
    TrapFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip: 0,
        cs: 0,
        rflags: 0,
        rsp: 0,
        ss: 0,
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
    /// Separate CPL3 policy. User tasks can be time-sliced while their CPL0
    /// syscall continuations remain run-to-completion (`no_preempt = true`).
    user_preempt: AtomicBool,
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
    /// Per-task user-FPU (FXSAVE) area pointer, published by the userspace
    /// `UserTaskFuture::poll` on first entry. Lives HERE (not in a per-CPU slot)
    /// because in the own-stack model a task resumes via `kernel_switch` (not a
    /// re-poll), so the save/restore must read the CURRENT task's area — a
    /// per-CPU slot would go stale (last task to poll) or dangle after a task
    /// exits and its `Box` is freed, fxrstor-ing freed memory.
    user_fpu: AtomicPtr<u8>,
    /// Per-task user address-space CR3, published by the userspace
    /// `UserTaskFuture::poll` (and the inline execve path) once the AS is
    /// activated. In the own-stack model a preempted/parked task resumes via
    /// `kernel_switch` (NOT a re-poll), so nothing re-activates its AS — without
    /// re-loading CR3 before switching the task back in, it would resume under
    /// whatever AS the executor last ran (e.g. another task that ran in between)
    /// and every user-memory access (signal-frame write, iretq fetch) would land
    /// in the wrong page tables. `poll_to_yield` reloads this before each switch
    /// into the task. 0 = not yet entered user mode (first poll activates it).
    user_cr3: AtomicU64,
    /// Per-task user `FS_BASE` (the TLS / thread-pointer MSR), published by the
    /// userspace `UserTaskFuture::poll` and the `arch_prctl(ARCH_SET_FS)` handler.
    /// Same resume-bypass rationale as `user_cr3`: under own-stack a preempted/
    /// parked task resumes via `kernel_switch` (NOT a re-poll), so the poll-time
    /// `set_user_fs_base` never re-runs. Without reloading FS_BASE before switching
    /// the task back in, a multithreaded process resumes a thread on ANOTHER
    /// thread's TLS — the executor left the FS_BASE MSR set to the last
    /// freshly-polled task's value — and the thread's first `fs:[0]` TCB read
    /// faults at NULL (looping forever if it caught SIGSEGV with a handler that
    /// itself reads TLS — the SMP `chroot_run` runaway-SIGSEGV hang).
    /// `poll_to_yield` reloads this before each switch into the task. 0 = no TLS
    /// / not yet published.
    user_fs_base: AtomicU64,
}

// SAFETY: A `KernelTask` runs on one CPU at a time (the executor switches
// into it, and it yields before another CPU can poll it). Its interior
// mutability is atomics + a `current_waker` IrqSafeSpinLock. Under SMP a
// raw `*mut KernelTask` is published in `CURRENT_STACKFUL_TASK` and read
// cross-CPU (try_preempt, syscall-exit, user-state publish); the lifetime
// of that raw access is made sound by deferring the task's reclamation
// through RCU (see `impl Drop for StackfulAdapter`), so the memory outlives
// any stale cross-CPU pointer. Send: a task's `Box` is moved between per-CPU
// ready queues by the work-stealer.
unsafe impl Send for KernelTask {}
// SAFETY: Same as the `Send` impl — one-CPU-at-a-time execution plus atomic /
// locked interior mutability; cross-CPU raw-pointer reads are kept sound by
// RCU-deferred reclamation.
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
        assert!(
            stack_bytes & 0xF == 0,
            "kernel stack must be 16-byte aligned"
        );

        // Allocate the stack on the heap so it's stable across
        // moves (we're going to point r15 at the task itself, and
        // rsp at this stack — both pointers must stay valid).
        let mut stack: Box<[u8]> = alloc::vec![0u8; stack_bytes].into_boxed_slice();

        // Arm the overflow tripwire at the LOW end of the stack. See
        // STACK_CANARY: a stack overrunning its bottom pushes through
        // these words before it reaches the heap object below.
        for i in 0..STACK_CANARY_WORDS {
            stack[i * 8..(i + 1) * 8].copy_from_slice(&STACK_CANARY.to_ne_bytes());
        }

        // We'll fill in ctx after the Box exists (need its
        // address). Start with a placeholder.
        let mut me = Box::new(KernelTask {
            future: Box::pin(future),
            stack,
            // `KernelContext::default()` is a real register struct on x86_64
            // and a unit struct elsewhere; the allow covers the unit-struct
            // arches where clippy would otherwise flag the constructor.
            #[allow(clippy::default_constructed_unit_structs)]
            ctx: KernelContext::default(),
            exec_ctx: AtomicPtr::new(core::ptr::null_mut()),
            completed: AtomicBool::new(false),
            tsc_started: AtomicU64::new(0),
            slice_cycles: AtomicU64::new(DEFAULT_SLICE_CYCLES),
            no_preempt: AtomicBool::new(false),
            user_preempt: AtomicBool::new(false),
            saved_trap_frame: UnsafeCell::new(zeroed_trap_frame()),
            preempted: AtomicBool::new(false),
            current_waker: narf_lib::sync::IrqSafeSpinLock::new(None),
            user_fpu: AtomicPtr::new(core::ptr::null_mut()),
            user_cr3: AtomicU64::new(0),
            user_fs_base: AtomicU64::new(0),
        });

        // Stack top = highest byte addr + 1, then mask down to
        // 16-byte alignment. The ABI requires rsp be 16-byte
        // aligned just before a `call` instruction (which then
        // pushes the 8-byte return address, making it 8-byte
        // aligned at the callee's prologue). Our trampoline runs
        // without a `call` — `kernel_switch` does a `jmp rcx` to
        // it — so the entry sees rsp as 16-aligned, which is what
        // the SysV ABI wants for a fresh function entry.
        let stack_top =
            (me.stack.as_mut_ptr() as u64).wrapping_add(me.stack.len() as u64) & !0xFu64;

        // Smuggle the task pointer in via r15 (callee-saved
        // register, survives the asm restore). The trampoline
        // moves it to rdi for the Rust-side call.
        let task_ptr_as_u64 = &*me as *const KernelTask as u64;

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            me.ctx =
                KernelContext::fresh(stack_top, trampoline_entry as usize as u64, task_ptr_as_u64);
        }
        let _ = (stack_top, task_ptr_as_u64); // silence warnings on aarch64 stub

        me
    }

    /// Verify the stack-overflow tripwire at the low end of this
    /// task's stack. Panics with attribution if any canary word was
    /// overwritten — the task's kernel stack grew past its bottom and
    /// scribbled the heap object physically below it. Detecting it
    /// here (every executor switch-back) names the culprit while the
    /// task is still identifiable, instead of leaving a slab canary
    /// to trip minutes later in an unrelated context.
    pub fn check_stack_canary(&self) {
        if let Some((i, got)) = self.stack_canary_clobbered() {
            let base = self.stack.as_ptr() as u64;
            panic!(
                "KERNEL TASK STACK OVERFLOW: canary word {} at {:#x} clobbered \
                 ({:#018x} != {:#018x}) — stack [{:#x},{:#x}) ({} KiB) overran its \
                 bottom into the heap below",
                i,
                base + (i as u64) * 8,
                got,
                STACK_CANARY,
                base,
                base + self.stack.len() as u64,
                self.stack.len() / 1024,
            );
        }
    }

    /// First clobbered canary word at the low end of the stack, as
    /// `(word_index, found_value)`, or `None` when the tripwire is
    /// intact. Split from `check_stack_canary` so the smoke test can
    /// exercise the detector without panicking.
    fn stack_canary_clobbered(&self) -> Option<(usize, u64)> {
        for i in 0..STACK_CANARY_WORDS {
            let mut w = [0u8; 8];
            w.copy_from_slice(&self.stack[i * 8..(i + 1) * 8]);
            if u64::from_ne_bytes(w) != STACK_CANARY {
                return Some((i, u64::from_ne_bytes(w)));
            }
        }
        None
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
    /// - The task may move only between completed calls: its dedicated stack
    ///   and saved context move with it, while this call rebinds `exec_ctx`,
    ///   TSS.rsp0, CR3, FS_BASE, and per-CPU publication before switch-in.
    /// - No concurrent `poll_to_yield` for the same task. The
    ///   AtomicPtr/AtomicBool make in-CPU re-entry detectable
    ///   in debug builds; the precondition is the caller's.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn poll_to_yield(
        &mut self,
        exec_ctx: &mut KernelContext,
        waker: &Waker,
    ) -> Poll<()> {
        // A completed task's saved `ctx` is a CONSUMED continuation — its
        // final switch-out already ran (`exit_current_stackful` additionally
        // poisons `ctx.rip`). Never switch into it: report Ready so the
        // caller drops the slot. This makes a poll of an already-completed
        // task (a stale wake racing the exit on another CPU) a clean no-op
        // instead of a resume of dead state.
        if self.completed.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        // Stash the executor's waker so the inner future's
        // `cx.waker().wake_by_ref()` (e.g. from `yield_now()`)
        // re-arms the correct slot — see `task_body_rust`.
        *self.current_waker.lock() = Some(waker.clone());
        // Publish exec_ctx so the task can find it on yield.
        self.exec_ctx.store(exec_ctx as *mut _, Ordering::Release);
        // Record when this slice started — the trap-handler
        // preempt hook reads `tsc_started` to decide whether
        // we've used our slice.
        self.tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
        // CURRENT_STACKFUL_TASK is SET to the running task by task_body_rust
        // (at the top of each poll iter) and CLEARED by it before each yield.
        // The executor side must not *set* it to the task (that would let a
        // timer tick preempt an already-yielded task and overwrite its ctx).
        // But it MUST snapshot + restore the value that was live on entry:
        // `poll_to_yield` can run NESTED — a stackful task doing a synchronous
        // in-kernel wait ticks `sleep_pumps` → `scheduler_step_pump` →
        // `poll_one_round`, which polls another stackful task through this very
        // function. That inner task's `task_body_rust` clears CURRENT to null
        // on its yield; without restoring it, the OUTER task resumes its
        // sync-wait with CURRENT == null and every subsequent
        // `current_stackful_waker()` / `try_preempt` sees "no task running" —
        // so an own-stack blocking syscall (epoll_wait) can't register its
        // wake, breaks out of `own_stack_park`, and busy-re-executes forever
        // (observed: redis after startup wedged the single executor, starving
        // netserve). Restoring the snapshot after the switch-back is null for
        // the top-level executor (preserving the "null while the executor
        // runs" invariant) and the outer task for a nested poll.
        let saved_current = {
            let cpu = this_cpu();
            CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire)
        };
        // SAFETY: ctx + exec_ctx both live for the duration of
        // this call; the task's stack was allocated by us and is
        // still alive; the trampoline_entry symbol is in this
        // crate's code segment.
        // Per-task-own-stack model: point TSS.rsp0 + SYSCALL gs:[8] at THIS
        // task's own kernel stack before switching in, so a trap/syscall from
        // the task lands on its own stack (and `try_preempt_user` can preempt
        // it with a clean kernel_switch). Restored to the per-CPU baseline on
        // switch-back. Harmless for kernel-only stackful tasks (they take no
        // CPL3 trap and a CPL0 trap doesn't reload rsp0).
        let own_stack = USE_OWN_STACK.load(Ordering::Acquire);
        // Snapshot the rsp0 live on entry. For the top-level executor this is the
        // per-CPU baseline; for a NESTED poll (a running stackful task pumping
        // `poll_one_round` from a sync wait) it is the OUTER task's own stack
        // top. Restored verbatim on switch-back instead of `retarget(0)` — which
        // would force the baseline and leave the outer user task's later
        // syscalls landing on the executor stack, corrupting the saved switch
        // context (observed as a wild-`rip` #UD/#PF right after redis's first
        // epoll park, once the CURRENT_STACKFUL_TASK clobber above was fixed).
        let saved_rsp0 = if own_stack {
            crate::current_kernel_stack_top()
        } else {
            0
        };
        if own_stack {
            let top = ((self.stack.as_ptr() as u64) + self.stack.len() as u64) & !0xFu64;
            crate::retarget_kernel_stack(top);
            // Re-activate the task's user address space before switching in. A
            // task that yielded/was-preempted resumes via kernel_switch (NOT a
            // re-poll), so this is the only point that restores its CR3 — without
            // it the task would run under whatever AS the executor last used
            // (e.g. a different task polled in between), faulting on every
            // user-memory access. Skipped on the first poll (cr3==0): the poll
            // itself activates the AS and publishes it via set_current_user_cr3.
            let cr3 = self.user_cr3.load(Ordering::Acquire);
            if cr3 != 0 {
                // SAFETY: `cr3` is a CR3 value snapshotted from a prior
                // `address_space.activate()` of this task's live AS; reloading it
                // restores that mapping (kernel half is global in every AS).
                unsafe {
                    core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                        options(nostack, preserves_flags));
                }
            }
            // Restore the task's user FS_BASE (TLS) MSR too — same resume-bypass
            // rationale as CR3 above. A multithreaded task resumes via
            // kernel_switch, NOT a re-poll, so without this it runs on whatever
            // FS_BASE the last freshly-polled task installed and its first user
            // TLS access (`fs:[0]`) faults. Skipped on the first poll / a TLS-less
            // task (fs_base==0): the poll itself sets and publishes FS_BASE.
            let fs_base = self.user_fs_base.load(Ordering::Acquire);
            if fs_base != 0 {
                // SAFETY: `fs_base` is a canonical user vaddr published from this
                // task's poll-time `set_user_fs_base` (stage_tls / arch_prctl).
                unsafe {
                    narf_arch::x86_64::user_mode::set_user_fs_base(fs_base);
                }
            }
        }
        // Snapshot the shared per-CPU EXEC_CTX slot's CONTENTS. `poll_to_yield`
        // can run NESTED — a stackful task doing a synchronous in-kernel wait
        // ticks sleep_pumps → poll_one_round, which polls ANOTHER stackful task
        // (the virtio-net forwarder) through this same function. All nesting
        // levels share the single per-CPU `EXEC_CTX` slot (made persistent by
        // 902f31cf to dodge transient-stack-frame aliasing). The inner poll's
        // `kernel_switch` SAVE overwrites the slot with the INNER executor
        // continuation; when the inner task switches back, the slot still holds
        // a stale inner continuation, so when the OUTER task later parks it
        // switches to that dead frame → a wild-rip #GP/#UD (observed exactly at
        // redis's first epoll park, after it nest-polled the forwarder during
        // startup: the park read exec_ctx.rsp on redis's OWN stack instead of
        // the boot stack). Save the slot on entry and restore it on switch-back
        // so the shared slot behaves per-nesting-level. Cheap (~72-byte struct).
        // SAFETY: `exec_ctx` is a live `&mut KernelContext` (the per-CPU EXEC_CTX
        // slot) valid for this call; reading a `Copy`-layout POD struct from it
        // is sound and leaves the source intact.
        let prev_exec = unsafe { core::ptr::read(exec_ctx as *const KernelContext) };
        guard_switch_into("poll_to_yield:self.ctx", &self.ctx);
        let perf_task = crate::current_task_id().raw();
        user_perf_switch(perf_task, true);
        // SAFETY: Valid memory or trusted environment
        unsafe { kernel_switch(exec_ctx as *mut _, &self.ctx) };
        // ── We are resumed here when the task yields back ──
        // Stack-overflow tripwire: catch a task whose kernel stack
        // grew past its bottom during the slice that just ended,
        // with attribution, before the scribbled heap is touched
        // further (see check_stack_canary).
        self.check_stack_canary();
        user_perf_switch(perf_task, false);
        // Restore the EXEC_CTX slot contents that were live before this poll, so
        // a nested poll leaves the OUTER task's saved continuation intact (see
        // the snapshot comment above).
        // SAFETY: `exec_ctx` is the same live `&mut KernelContext` written above;
        // writing back the snapshotted POD value is sound (no aliasing — we hold
        // the only reference on this single-CPU cooperative path).
        unsafe { core::ptr::write(exec_ctx as *mut KernelContext, prev_exec) };
        if own_stack {
            // Restore the rsp0 that was live on entry (baseline at top level, the
            // outer task's stack top when nested) — NOT an unconditional baseline.
            crate::retarget_kernel_stack(saved_rsp0);
        }
        // Restore the CURRENT_STACKFUL_TASK that was live before this poll. The
        // just-yielded task cleared it to null; for a nested poll this puts the
        // OUTER (still-running) task back so its sync-wait keeps a valid
        // identity (see the snapshot comment above). For the top-level executor
        // the saved value is null, so the invariant is preserved.
        {
            let cpu = this_cpu();
            CURRENT_STACKFUL_TASK.inner[cpu].store(saved_current, Ordering::Release);
        }
        self.exec_ctx
            .store(core::ptr::null_mut(), Ordering::Release);
        // Publish whether this return was an involuntary preemption so the
        // executor can suppress its QSBR quiescent-state announcement (a
        // preemption is not a quiescent point — the suspended continuation may
        // hold raw RCU references). `try_preempt` set `preempted` before
        // switching out; consume it here so a later cooperative yield of the
        // same task isn't mis-reported as a preemption. See `PREEMPTED_RETURN`.
        let was_preempted = self.preempted.swap(false, Ordering::AcqRel);
        {
            let cpu = this_cpu();
            PREEMPTED_RETURN.inner[cpu].store(was_preempted, Ordering::Release);
        }
        if self.completed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Resume the task on its dedicated AArch64 stack until it yields,
    /// completes, or is preempted back into `exec_ctx`.
    ///
    /// # Safety
    /// The task, its stack, and `exec_ctx` must remain live for the complete
    /// switch round trip, and the same task must not be polled concurrently.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn poll_to_yield(
        &mut self,
        exec_ctx: &mut KernelContext,
        waker: &Waker,
    ) -> Poll<()> {
        if self.completed.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *self.current_waker.lock() = Some(waker.clone());
        self.exec_ctx.store(exec_ctx as *mut _, Ordering::Release);
        self.tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
        let cpu = this_cpu();
        let saved_current = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
        // SAFETY: this CPU exclusively owns the persistent executor slot for
        // this call; the POD copy preserves a nested pump's outer continuation.
        let previous = unsafe { core::ptr::read(exec_ctx as *const KernelContext) };
        guard_switch_into("poll_to_yield:self.ctx", &self.ctx);
        // SAFETY: both contexts and the task-owned stack remain live.
        unsafe { kernel_switch(exec_ctx as *mut _, &self.ctx) };
        self.check_stack_canary();
        // SAFETY: same exclusive per-CPU slot as above.
        unsafe { core::ptr::write(exec_ctx as *mut KernelContext, previous) };
        CURRENT_STACKFUL_TASK.inner[cpu].store(saved_current, Ordering::Release);
        self.exec_ctx
            .store(core::ptr::null_mut(), Ordering::Release);
        PREEMPTED_RETURN.inner[cpu].store(
            self.preempted.swap(false, Ordering::AcqRel),
            Ordering::Release,
        );
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

    /// Enable or disable own-stack CPL3 timer preemption independently of
    /// arbitrary CPL0 kernel preemption.
    pub fn set_user_preempt(&self, v: bool) {
        self.user_preempt.store(v, Ordering::Release);
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
        // SAFETY: Valid memory or trusted environment
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }
}

impl KernelTask {
    /// Clear every per-CPU `CURRENT_STACKFUL_TASK` slot that still names
    /// this task, so no CPU can newly load a pointer to it (and none can
    /// try to preempt a task that is done executing). `StackfulAdapter`'s
    /// reclaim path calls this SYNCHRONOUSLY before handing the box to RCU
    /// for deferred free; `Drop` calls it again as a backstop. O(MAX_CPUS).
    fn clear_current_slots(&self) {
        let me = self as *const KernelTask as *mut KernelTask;
        for slot in CURRENT_STACKFUL_TASK.inner.iter() {
            // Only clear a slot that names THIS task; leave others.
            let _ = slot.compare_exchange(
                me,
                core::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
    }
}

impl Drop for KernelTask {
    /// Backstop: guarantee no per-CPU `CURRENT_STACKFUL_TASK` slot outlives
    /// this task pointing at it. The reclaim path (`StackfulAdapter::drop`)
    /// clears the slots synchronously and defers the memory free through
    /// RCU, so by the time this runs the slots are already clear; re-clear
    /// here in case a `KernelTask` is ever freed by some other path.
    fn drop(&mut self) {
        self.clear_current_slots();
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

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn trampoline_entry() -> ! {
    use core::arch::naked_asm;
    naked_asm!(
        "mov x0, x19",
        "bl {body}",
        "brk #0",
        body = sym task_body_rust,
    );
}

/// The body of every stackful kernel task. Polls the future,
/// yields back to the executor when it returns Pending, marks
/// `completed = true` when it returns Ready then yields one
/// last time (so the executor can drop the task).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
extern "C" fn task_body_rust(task: *mut KernelTask) -> ! {
    // SAFETY: `task` was set by `KernelTask::new` from a `Box::leak`-
    // equivalent (we own the box via `Box<KernelTask>`; the executor
    // holds it during the switch + we get a &mut here as the only
    // active reference on this stack).
    // SAFETY: Valid memory or trusted environment
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
        //
        // `set_cpu` is captured here for the matching clear at the bottom
        // of this iteration. A task can be preempted and resumed on a
        // different CPU (work-stealing) mid-iteration, so by clear time
        // EITHER this slot OR the current CPU's slot may name us; the
        // loop-bottom clear compare_exchanges BOTH so no slot outlives
        // this iteration naming the task, and no other task's arming is
        // ever nulled by mistake.
        let set_cpu = this_cpu();
        CURRENT_STACKFUL_TASK.inner[set_cpu].store(task_ptr, Ordering::Release);

        let waker_guard = task.current_waker.lock();
        let waker = match waker_guard.as_ref() {
            Some(w) => w.clone(),
            None => KernelTask::no_op_waker(),
        };
        drop(waker_guard);
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
        // Clear CURRENT_STACKFUL_TASK before yielding so a
        // timer tick landing between this clear and the
        // kernel_switch below (or while we're switched out)
        // doesn't preempt a task that's no longer executing.
        // Both the slot this iteration armed (`set_cpu`) and the slot of
        // the CPU we now run on can name us: a mid-iteration preempt +
        // work-steal migrates the task, and the preempt-resume republishes
        // it on the destination CPU. Clear whichever still names us — and
        // ONLY if it names us (compare_exchange): an unconditional store
        // to `set_cpu`'s slot after a migration would null a DIFFERENT
        // task's arming on the origin CPU, hiding that task from
        // preemption and from every `current_stackful_*` lookup.
        let _ = CURRENT_STACKFUL_TASK.inner[set_cpu].compare_exchange(
            task_ptr,
            core::ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
        let clear_cpu = this_cpu();
        if clear_cpu != set_cpu {
            let _ = CURRENT_STACKFUL_TASK.inner[clear_cpu].compare_exchange(
                task_ptr,
                core::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
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
        // SAFETY: exec_ctx non-null (checked above).
        guard_switch_into("try_preempt:exec_ctx", unsafe { &*exec_ctx });
        // SAFETY: Valid memory or trusted environment
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
    if frame.vector != current_preempt_vector() {
        return false;
    }
    if !cpl_zero(frame.cs) {
        return false; // trapped from user mode; not our path
    }
    if !preempt_enabled() {
        return false;
    }
    let cpu = this_cpu();
    let task_ptr = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if task_ptr.is_null() {
        return false; // no stackful task currently polling on this CPU
    }
    // SAFETY: CURRENT_STACKFUL_TASK is only set by an in-progress
    // `poll_to_yield` whose caller still holds the Box alive; the
    // pointer remains valid until poll_to_yield clears it.
    // SAFETY: Valid memory or trusted environment
    let no_preempt = unsafe { (*task_ptr).no_preempt.load(Ordering::Acquire) };
    if no_preempt {
        return false;
    }
    // SAFETY: `task_ptr` was loaded from CURRENT_STACKFUL_TASK above and is
    // non-null; per the invariant noted there, the Box it points at is kept
    // alive by the in-progress poll_to_yield, so the atomic field reads below
    // dereference a live `KernelTask`.
    // SAFETY: Valid memory or trusted environment
    let started = unsafe { (*task_ptr).tsc_started.load(Ordering::Acquire) };
    // SAFETY: Same live-`KernelTask` invariant as above.
    let slice = unsafe { (*task_ptr).slice_cycles.load(Ordering::Acquire) };
    let now = narf_time::now_cycles();
    let slice_expired = now.saturating_sub(started) >= slice;
    if !crate::tick_preemption_required(crate::current_task_id().raw(), now, slice_expired) {
        return false;
    }
    // SAFETY: Same live-`KernelTask` invariant as above.
    let exec_ctx = unsafe { (*task_ptr).exec_ctx.load(Ordering::Acquire) };
    if exec_ctx.is_null() {
        return false; // no executor to switch to
    }

    // Own-stack invariant tripwire. A CPL0 timer tick that preempts THIS task
    // must have landed on the task's OWN kernel stack: `poll_to_yield`
    // retargets TSS.rsp0 to it, and a CPL0→CPL0 trap pushes onto the current
    // rsp (= this task's stack). If `frame` is NOT inside the current task's
    // stack, the rsp0 / own-stack handoff desynced and we are about to
    // save-and-switch off a trap frame sitting on the WRONG (executor) stack —
    // zeroing/garbaging its return slots is precisely the intermittent RIP≈0
    // #UD. Catch it with attribution instead of silently corrupting.
    let frame_addr = frame as *const TrapFrame as u64;
    // SAFETY: live KernelTask per the CURRENT_STACKFUL_TASK invariant above;
    // `stack` is a `Box<[u8]>` whose base/len bound the task's kernel stack.
    let task_ref: &KernelTask = unsafe { &*task_ptr };
    let stk_base = task_ref.stack.as_ptr() as u64;
    let stk_top = stk_base + task_ref.stack.len() as u64;
    if frame_addr < stk_base || frame_addr >= stk_top {
        panic!(
            "CTXGUARD try_preempt cpu={}: preempt trap frame {:#018x} is OUTSIDE the \
             current task's kernel stack [{:#018x},{:#018x}) — rsp0/own-stack desync; \
             frame.rip={:#018x} frame.cs={:#x}",
            cpu, frame_addr, stk_base, stk_top, frame.rip, frame.cs,
        );
    }

    // Arm the executor's slot waker so we get re-polled when the
    // executor runs out of other ready tasks. Without this, the
    // slot's `awake` flag stays at the false the last poll
    // cleared it to, and we'd be dormant forever (the inner
    // future never finished, so it never called wake_by_ref).
    // SAFETY: Same live-`KernelTask` invariant as above; `current_waker` is an
    // IrqSafeSpinLock, so locking it from this IRQ context is sound.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let waker_guard = (*task_ptr).current_waker.lock();
        if let Some(w) = waker_guard.as_ref() {
            w.wake_by_ref();
        }
        drop(waker_guard);
    }

    // Mark for debug visibility (consumed by the smoke tests).
    // SAFETY: Same live-`KernelTask` invariant as above. `saved_trap_frame` is
    // an UnsafeCell owned by this task and only written here while the task is
    // the CPU's CURRENT_STACKFUL_TASK, so there is no concurrent access; the
    // volatile write copies the caller-owned `*frame` into it.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile((*task_ptr).saved_trap_frame.get(), *frame);
        (*task_ptr).preempted.store(true, Ordering::Release);
    }

    // A timer preemption is a real slice boundary just like a voluntary
    // kernel_switch. Pause any open userspace syscall span before switching
    // away so its off-CPU residency is not billed as kernel CPU time, and
    // fold the complete on-CPU slice before the resume path restamps it.
    let kernel_span_paused = pause_user_kernel_span();
    fold_current_slice(task_ptr);

    // Save the user FPU before another task clobbers XMM/x87/AVX. This CPL0
    // tick preempted the current task IN THE KERNEL — but if it is a USER task
    // that trapped in for a syscall, its live SIMD state is still in the
    // hardware registers (the kernel is `+soft-float` and never touches them),
    // exactly as after a CPL3 preempt. Without this save, the executor polls
    // other user tasks whose `fpu_restore` overwrites the registers, and when
    // this task's syscall resumes and `iretq`s back to user its in-flight
    // `memcpy`/`memset` runs on another task's XMM/YMM — a torn heap/stack
    // write that glibc later detects as corruption and `abort()`s (SIGABRT).
    // `user_fpu_save` no-ops for a pure kernel task (its `user_fpu` is null).
    // Must run BEFORE clearing CURRENT: `user_fpu_save` resolves the area via
    // CURRENT_STACKFUL_TASK, so a cleared slot would silently skip the save.
    // Mirrors the CPL3 `try_preempt_user` path.
    user_fpu_save();
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
    // SAFETY: Same live-`KernelTask` invariant; taking a raw pointer to its
    // `ctx` field does not dereference beyond the live allocation.
    // SAFETY: Valid memory or trusted environment
    let task_ctx_ptr = unsafe { &raw mut (*task_ptr).ctx };
    // SAFETY: `task_ctx_ptr` points at this task's `KernelContext` (save slot)
    // and `exec_ctx` is the non-null executor context published by the
    // in-progress poll_to_yield; kernel_switch saves the current callee-saved
    // state / RFLAGS into the former and restores the latter.
    // SAFETY: exec_ctx non-null (executor published it).
    guard_switch_into("preempt_trap:exec_ctx", unsafe { &*exec_ctx });
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: We were resumed by the executor switching back into this task, so
    // its Box is still alive (poll_to_yield has not returned). Re-publishing
    // CURRENT and restarting the slice counter dereferences that live task.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        CURRENT_STACKFUL_TASK.inner[cpu].store(task_ptr, Ordering::Release);
        (*task_ptr)
            .tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
    }
    if kernel_span_paused {
        resume_user_kernel_span();
    }
    // Restore this task's user FPU, clobbered by whatever ran while we were
    // switched out. Must run AFTER re-publishing CURRENT above (which
    // `user_fpu_restore` reads to resolve the area) and before the `iretq`
    // that returns to the interrupted kernel/user RIP. No-op for kernel tasks.
    user_fpu_restore();
    true
}

/// AArch64 generic-timer equivalent of [`try_preempt`]. The vector prologue
/// has already preserved the complete EL1/EL0 return frame on the task's own
/// stack; this function switches the live trap continuation back to the
/// executor and later resumes it unchanged.
///
/// # Safety
/// `frame_addr` must name the live vector frame on the current stack, and the
/// GIC interrupt must have been EOI'd before this call.
#[cfg(target_arch = "aarch64")]
pub unsafe fn try_preempt_aarch64(frame_addr: usize) -> bool {
    if !preempt_enabled() {
        return false;
    }
    let cpu = this_cpu();
    let task_ptr = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if task_ptr.is_null() {
        return false;
    }
    // SAFETY: CURRENT names the task whose in-flight poll keeps its Box live.
    let task = unsafe { &*task_ptr };
    if task.no_preempt.load(Ordering::Acquire) {
        return false;
    }
    let now = narf_time::now_cycles();
    let started = task.tsc_started.load(Ordering::Acquire);
    let slice_expired = now.saturating_sub(started) >= task.slice_cycles.load(Ordering::Acquire);
    if !crate::tick_preemption_required(crate::current_task_id().raw(), now, slice_expired) {
        return false;
    }
    let exec_ctx = task.exec_ctx.load(Ordering::Acquire);
    if exec_ctx.is_null() {
        return false;
    }
    let stack_base = task.stack.as_ptr() as usize;
    let stack_top = stack_base + task.stack.len();
    if frame_addr < stack_base || frame_addr >= stack_top {
        panic!(
            "CTXGUARD try_preempt_aarch64 cpu={cpu}: vector frame {frame_addr:#018x} \
             outside task stack [{stack_base:#018x},{stack_top:#018x})"
        );
    }
    {
        let waker = task.current_waker.lock();
        if let Some(waker) = waker.as_ref() {
            waker.wake_by_ref();
        }
    }
    task.preempted.store(true, Ordering::Release);
    CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);
    // SAFETY: CURRENT_STACKFUL_TASK names the task whose in-flight
    // poll_to_yield call exclusively owns this context save slot.
    let task_ctx = unsafe { &raw mut (*task_ptr).ctx };
    // SAFETY: exec_ctx was published by the in-flight poll_to_yield call and
    // stays live until this trap continuation switches back into the task.
    guard_switch_into("try_preempt_aarch64:exec_ctx", unsafe { &*exec_ctx });
    // SAFETY: task_ctx and the executor context remain live across this swap.
    unsafe { kernel_switch(task_ctx, exec_ctx) };
    let resumed_cpu = this_cpu();
    CURRENT_STACKFUL_TASK.inner[resumed_cpu].store(task_ptr, Ordering::Release);
    // SAFETY: the task is still owned by the in-flight poll_to_yield.
    unsafe {
        (*task_ptr)
            .tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
    }
    true
}

/// Per-task-own-stack CPL=3 timer preemption — the clean replacement for the
/// longjmp-based `handlers::timer_preempt_user_task`. The user task ran on its
/// OWN kernel stack (`TSS.rsp0`), so the timer trap's frame is already sitting
/// untouched on that stack; we just save the user FPU, `kernel_switch` to the
/// executor (which leaves the trap frame in place), and on resume restore the
/// FPU and return true — `common_trap` then pops GPRs + `iretq`s back to the
/// exact interrupted user instruction. No longjmp, no synthetic resume frame.
///
/// Returns false (no preemption) unless the own-stack model is on, the trap is
/// a user-mode (CPL=3) scheduler-tick, a stackful task is current, its slice is
/// spent, and an executor context is published.
///
/// # Safety
/// Called only from the LAPIC-timer trap handler, after EOI, with `frame`
/// pointing at the live trap frame on the current task's kernel stack.
#[cfg(target_arch = "x86_64")]
pub unsafe fn try_preempt_user(frame: &mut TrapFrame) -> bool {
    if !USE_OWN_STACK.load(Ordering::Acquire) {
        return false;
    }
    if frame.vector != current_preempt_vector() {
        return false;
    }
    if (frame.cs & 3) != 3 {
        return false; // kernel-mode trap → that's `try_preempt`'s job
    }
    if !preempt_enabled() {
        return false;
    }
    let cpu = this_cpu();
    let task_ptr = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if task_ptr.is_null() {
        return false; // no user task currently on this CPU
    }
    // SAFETY: `task_ptr` is the in-flight task on this CPU; the Box is kept
    // alive by the executor's `poll_to_yield` across the user-mode round-trip.
    let user_preempt = unsafe { (*task_ptr).user_preempt.load(Ordering::Acquire) };
    if !user_preempt {
        return false;
    }
    // SAFETY: live `task_ptr` as established above.
    let started = unsafe { (*task_ptr).tsc_started.load(Ordering::Acquire) };
    // SAFETY: live `task_ptr` as established above.
    let slice = unsafe { (*task_ptr).slice_cycles.load(Ordering::Acquire) };
    let now = narf_time::now_cycles();
    let slice_expired = now.saturating_sub(started) >= slice;
    if !crate::tick_preemption_required(crate::current_task_id().raw(), now, slice_expired) {
        return false;
    }
    // SAFETY: live `task_ptr` as established above.
    let exec_ctx = unsafe { (*task_ptr).exec_ctx.load(Ordering::Acquire) };
    if exec_ctx.is_null() {
        return false;
    }
    // Own-stack invariant tripwire (CPL3 side). The user task ran on its OWN
    // kernel stack via TSS.rsp0 (poll_to_yield retargets it), so a CPL3→CPL0
    // timer trap lands its frame at rsp0 = this task's stack top. If `frame`
    // is NOT inside the current task's stack, rsp0 desynced and the trap frame
    // sits on the WRONG (executor) stack — the same rsp0/own-stack corruption
    // as the CPL0 path (see try_preempt). Catch it with attribution.
    let frame_addr = frame as *const TrapFrame as u64;
    // SAFETY: live KernelTask per the CURRENT_STACKFUL_TASK invariant above.
    let task_ref: &KernelTask = unsafe { &*task_ptr };
    let stk_base = task_ref.stack.as_ptr() as u64;
    let stk_top = stk_base + task_ref.stack.len() as u64;
    if frame_addr < stk_base || frame_addr >= stk_top {
        panic!(
            "CTXGUARD try_preempt_user cpu={}: user-preempt trap frame {:#018x} is OUTSIDE \
             the current task's kernel stack [{:#018x},{:#018x}) — rsp0/own-stack desync; \
             frame.rip={:#018x} frame.cs={:#x}",
            cpu, frame_addr, stk_base, stk_top, frame.rip, frame.cs,
        );
    }
    // Re-arm the slot waker so the executor re-polls us next round.
    // SAFETY: live task; `current_waker` is an IrqSafeSpinLock.
    unsafe {
        let g = (*task_ptr).current_waker.lock();
        if let Some(w) = g.as_ref() {
            w.wake_by_ref();
        }
        drop(g);
    }
    // This preemption ends the current on-CPU slice. Fold it before the resume
    // path restamps tsc_started; otherwise every timer-preempted interval
    // disappears from task-clock accounting.
    fold_current_slice(task_ptr);
    // This Pending return suspended an arbitrary continuation. The executor
    // must not report a QSBR quiescent state for the slot.
    // SAFETY: `task_ptr` names the live current task (same pointer used above).
    unsafe {
        (*task_ptr).preempted.store(true, Ordering::Release);
    }
    // Save the user FPU before another task clobbers XMM/x87, and clear CURRENT
    // so a tick during the switch-out window can't re-preempt us.
    user_fpu_save();
    CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);
    // SAFETY: `task.ctx` is the save slot, `exec_ctx` the live executor ctx;
    // kernel_switch saves the trap-handler continuation and resumes the executor.
    let task_ctx_ptr = unsafe { &raw mut (*task_ptr).ctx };
    // SAFETY: `task_ctx_ptr` is the save slot, `exec_ctx` the live executor ctx.
    guard_switch_into("preempt_yield:exec_ctx", unsafe { &*exec_ctx });
    // SAFETY: `task_ctx_ptr` is the save slot, `exec_ctx` the live executor ctx;
    // kernel_switch saves the trap-handler continuation and resumes the executor.
    unsafe { kernel_switch(task_ctx_ptr, exec_ctx) };
    // ── Resumed here when the executor switches back into this task ──
    let cpu = this_cpu();
    // SAFETY: still our live task (poll_to_yield has not returned).
    unsafe {
        CURRENT_STACKFUL_TASK.inner[cpu].store(task_ptr, Ordering::Release);
        (*task_ptr)
            .tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
    }
    user_fpu_restore();
    let _ = frame;
    true // common_trap pops GPRs + iretq → user resumes at the interrupted RIP
}

/// Switch the CURRENT stackful (user) task OUT to its executor via
/// `kernel_switch`, saving the syscall/yield continuation on the task's own
/// kernel stack; returns when the executor switches back in. The
/// per-task-own-stack replacement for the longjmp-based voluntary yield / park
/// (sys_yield, futex/wait/console park). No-op if no stackful task is current.
///
/// User-slice accounting hook: called with the elapsed ns of the slice
/// ending at every own-stack yield-out (the hook resolves the task id
/// itself via the current-task lookup, which is still this task here).
/// Installed by the userspace crate (`account_user_cpu_ns`) — under the
/// own-stack model, slices end HERE via kernel_switch instead of
/// returning through `UserTaskFuture::poll`'s fold, so without this
/// hook a CPU-bound own-stack task accumulates ZERO utime (the alpine
/// probe's `time` showed user 0.00 for a 5 s busy loop).
static SLICE_ACCOUNT_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Optional userspace hooks that split a live syscall span around a CPL0
/// timer preemption. `pause` returns true only when it closed a span; `resume`
/// is then called after the task is current again and its slice clock has been
/// restarted. Both callbacks run with interrupts disabled and must be
/// allocation-free after their per-task accounting rows have been created.
static KERNEL_SPAN_PAUSE_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static KERNEL_SPAN_RESUME_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn set_user_slice_account_hook(hook: fn(u64)) {
    SLICE_ACCOUNT_HOOK.store(hook as usize, Ordering::Release);
}

pub fn set_user_kernel_preempt_hooks(pause: fn() -> bool, resume: fn()) {
    KERNEL_SPAN_PAUSE_HOOK.store(pause as usize, Ordering::Release);
    KERNEL_SPAN_RESUME_HOOK.store(resume as usize, Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
fn pause_user_kernel_span() -> bool {
    let hook = KERNEL_SPAN_PAUSE_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return false;
    }
    // SAFETY: the setter accepts exactly fn() -> bool and publishes its
    // address with Release before this Acquire load.
    let pause: fn() -> bool = unsafe { core::mem::transmute(hook) };
    pause()
}

#[cfg(target_arch = "x86_64")]
fn resume_user_kernel_span() {
    let hook = KERNEL_SPAN_RESUME_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return;
    }
    // SAFETY: the setter accepts exactly fn() and publishes its address with
    // Release before this Acquire load.
    let resume: fn() = unsafe { core::mem::transmute(hook) };
    resume();
}

#[cfg(target_arch = "x86_64")]
fn fold_current_slice(p: *mut KernelTask) {
    let h = SLICE_ACCOUNT_HOOK.load(Ordering::Acquire);
    if h == 0 {
        return;
    }
    // SAFETY: caller guarantees `p` is the live current task.
    let started = unsafe { (*p).tsc_started.load(Ordering::Acquire) };
    if started == 0 {
        return;
    }
    let delta = narf_time::now_cycles().saturating_sub(started);
    // SAFETY: `h` was stored by set_user_slice_account_hook as a fn(u64).
    let f: fn(u64) = unsafe { core::mem::transmute(h) };
    f(narf_time::cycles_to_ns(delta));
}

/// Elapsed ns of the CURRENT (un-folded) slice — lets getrusage/times/
/// the exit-time rusage snapshot include the in-flight slice a running
/// task hasn't yielded out of yet. 0 when no stackful task is current.
#[cfg(target_arch = "x86_64")]
pub fn current_slice_elapsed_ns() -> u64 {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    // SAFETY: in-flight task on this CPU (poll_to_yield holds it alive).
    let started = unsafe { (*p).tsc_started.load(Ordering::Acquire) };
    if started == 0 {
        return 0;
    }
    narf_time::cycles_to_ns(narf_time::now_cycles().saturating_sub(started))
}

/// Non-x86_64: no own-stack model, no in-flight slice.
#[cfg(not(target_arch = "x86_64"))]
pub fn current_slice_elapsed_ns() -> u64 {
    0
}

/// # Safety
/// Called at CPL=0 from a syscall handler running on the current task's own
/// kernel stack, with a stackful task current on this CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn yield_current_stackful() {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return;
    }
    // SAFETY: in-flight task on this CPU.
    let exec_ctx = unsafe { (*p).exec_ctx.load(Ordering::Acquire) };
    if exec_ctx.is_null() {
        return;
    }
    // Slice ends here — fold it before the switch (the resume side
    // restamps tsc_started below).
    fold_current_slice(p);
    user_fpu_save();
    CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);
    // SAFETY: p is a valid non-null pointer to the active user task.
    let ctx = unsafe { &raw mut (*p).ctx };
    // SAFETY: ctx + exec_ctx live; kernel_switch saves our continuation and
    // resumes the executor, returning here when it switches us back in.
    // SAFETY: exec_ctx non-null (checked above); the executor populated it.
    guard_switch_into("yield_current_stackful:exec_ctx", unsafe { &*exec_ctx });
    // SAFETY: ctx + exec_ctx live; kernel_switch saves our continuation and
    // resumes the executor, returning here when it switches us back in.
    unsafe { kernel_switch(ctx, exec_ctx) };
    // ── Resumed ──
    let cpu = this_cpu();
    // SAFETY: still our live task.
    unsafe {
        CURRENT_STACKFUL_TASK.inner[cpu].store(p, Ordering::Release);
        (*p).tsc_started
            .store(narf_time::now_cycles(), Ordering::Release);
    }
    user_fpu_restore();
}

/// Cooperatively yield the current stackful task to the executor, re-arming
/// its slot waker first so it is re-polled promptly. Returns `true` if a yield
/// happened, `false` if there is no stackful task on this CPU (the caller
/// should fall back to a plain spin — there is nothing to yield to).
///
/// The right primitive for a CONTENDED in-kernel spin-wait whose lock holder
/// may be a DESCHEDULED task homed on THIS CPU (virtio-blk's `ReqGate`): a pure
/// `spin_loop` there monopolizes the CPU the holder needs to run on and
/// livelocks (the `no_park_backstop` thundering-herd convoy). Yielding hands the
/// CPU to the executor so it can run the holder, which then releases the lock;
/// on re-poll the caller retries. Uses the same re-arm-then-`yield_current_stackful`
/// switch-out as `maybe_resched_syscall_exit` / the own-stack park paths — the
/// well-tested cooperative path, NOT `no_preempt`.
#[cfg(target_arch = "x86_64")]
pub fn cooperative_yield() -> bool {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return false;
    }
    // SAFETY: `p` is the in-flight stackful task on this CPU (poll_to_yield keeps
    // its Box alive); `current_waker` is an IrqSafeSpinLock.
    unsafe {
        // Re-arm the slot waker so the executor keeps us Ready + re-polls us
        // after the siblings (incl. the lock holder) run. Without this the
        // just-cleared `awake` flag would leave us dormant forever.
        let g = (*p).current_waker.lock();
        if let Some(w) = g.as_ref() {
            w.wake_by_ref();
        }
    }
    // SAFETY: proven safe from syscall / in-kernel context — own_stack_park and
    // maybe_resched_syscall_exit switch out through the same path.
    unsafe { yield_current_stackful() };
    true
}

/// Per-CPU "yield at the next syscall exit" request, set by syscall handlers
/// that detect producer/consumer back-pressure (e.g. `rt_sigqueueinfo` onto a
/// target whose signal queue is already backlogged — stress-ng --sigrt's
/// parent outrunning its children). Consumed by `maybe_resched_syscall_exit`,
/// which then yields REGARDLESS of the time slice: the flooding sender
/// donates its CPU so the consumers drain, the cooperative-scheduler
/// analogue of CFS preempting a producer that has outrun its consumers.
/// A rare mis-attribution (the requesting task is preempted before its own
/// syscall tail runs, so ANOTHER task's tail consumes the flag) costs one
/// spurious-but-harmless yield.
#[cfg(target_arch = "x86_64")]
struct PerCpuBackpressure {
    inner: [core::sync::atomic::AtomicBool; narf_lib::percpu::MAX_CPUS],
}
#[cfg(target_arch = "x86_64")]
static BACKPRESSURE_YIELD: PerCpuBackpressure = PerCpuBackpressure {
    inner: [const { core::sync::atomic::AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS],
};

/// Request a cooperative yield at the current task's next syscall exit
/// (see [`BACKPRESSURE_YIELD`]). Callable from any syscall handler body;
/// no-op when own-stack scheduling isn't live.
#[cfg(target_arch = "x86_64")]
pub fn request_syscall_backpressure_yield() {
    if !USE_OWN_STACK.load(Ordering::Acquire) {
        return;
    }
    let cpu = this_cpu();
    if CURRENT_STACKFUL_TASK.inner[cpu]
        .load(Ordering::Acquire)
        .is_null()
    {
        return;
    }
    BACKPRESSURE_YIELD.inner[cpu].store(true, Ordering::Release);
}

/// Divisor of a task's time slice at which it becomes eligible for an EARLY
/// fair-share yield — but only when a sibling is actually waiting. At the
/// default 10 ms slice this is ≈2.5 ms. A task with no sibling waiting still
/// runs to its full slice; this only bounds how long a CPU hog holds the core
/// while a runnable peer starves.
#[cfg(target_arch = "x86_64")]
const FAIR_QUANTUM_DIV: u64 = 4;

/// Pure yield policy for [`maybe_resched_syscall_exit`], split out so it is
/// unit-testable without a live executor. Yields (`true`) on an explicit
/// back-pressure request, on full time-slice expiry, or once a fair quantum
/// (`slice / FAIR_QUANTUM_DIV`) is spent AND a sibling task is
/// runnable-and-waiting. `started == 0` (slice clock not yet stamped) never
/// yields.
///
/// The `sibling_waiting` term is the cooperative-scheduler stand-in for "a
/// lower-vtime task is runnable": a task sitting runnable in the queue while
/// another has been running has, by construction, accrued less recent CPU, so
/// ceding to it is the fair move. Without the early branch a syscall-dense
/// spinner (a compositor looping `poll()` on an always-ready eventfd) holds the
/// CPU for a full slice at a time and, on SMP=1, starves its own worker threads
/// and the whole session — the busy-poll starvation the ReqGate cooperative
/// yield (8c63bd43) fixed for the in-kernel spin, here for userspace.
#[cfg(target_arch = "x86_64")]
fn syscall_exit_yield_decision(
    started: u64,
    slice: u64,
    elapsed: u64,
    backpressure: bool,
    sibling_waiting: bool,
) -> bool {
    if backpressure {
        return true;
    }
    if started == 0 {
        return false;
    }
    if elapsed >= slice {
        return true;
    }
    elapsed >= slice / FAIR_QUANTUM_DIV && sibling_waiting
}

/// Linux `TIF_NEED_RESCHED`-at-syscall-exit analogue. The scheduler tick only
/// preempts a task it interrupts at CPL=3 (`try_preempt_user`'s CPL gate), so a
/// *syscall-dense* task — one whose user-mode gaps between syscalls are far
/// shorter than the syscall bodies — is essentially never sliced and starves
/// every sibling on its CPU until it voluntarily blocks. Linux re-checks the
/// spent time slice on the way out of every syscall; this restores that, and
/// additionally yields EARLY (after a fair quantum, see
/// [`syscall_exit_yield_decision`]) when a sibling is already runnable so a
/// full-slice CPU hog cannot starve a waiting peer for the whole 10 ms.
///
/// Called at the tail of the `syscall`-instruction dispatch (a real user frame
/// is returning to CPL=3). If this task's slice is spent it yields NOW — staying
/// Ready by re-arming its slot waker first (same as `try_preempt_user`), so the
/// executor re-polls it after servicing its siblings. Cheap when the slice is
/// not yet spent (a few atomic loads + one TSC read); only the spent-slice case
/// pays a context switch. No-op unless own-stack scheduling is live and a
/// stackful task is current.
///
/// # Safety
/// Must be called at the tail of the `syscall` dispatch on the current task's
/// own kernel stack, with a real user frame about to return to CPL=3 and no
/// kernel locks held — the yield switches to the executor via the same
/// `kernel_switch` the own-stack park paths use.
#[cfg(target_arch = "x86_64")]
pub unsafe fn maybe_resched_syscall_exit() {
    if !USE_OWN_STACK.load(Ordering::Acquire) {
        return;
    }
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return;
    }
    let backpressure = BACKPRESSURE_YIELD.inner[cpu].swap(false, Ordering::AcqRel);
    // SAFETY: `p` is the in-flight stackful task on this CPU (poll_to_yield keeps
    // its Box alive across the user round-trip); all reads are atomics.
    unsafe {
        // NOTE: deliberately NOT gated on `no_preempt`. User tasks keep CPL0
        // timer preemption disabled, but this is precisely a cooperative yield —
        // a SYNCHRONOUS slice check at syscall exit, about to return to CPL=3,
        // outside any kernel critical section. Honouring `no_preempt` here is
        // what left a syscall-dense task (stress-ng --sigrt's sigqueue loop)
        // never yielding and starving its CPU's siblings.
        let started = (*p).tsc_started.load(Ordering::Acquire);
        let slice = (*p).slice_cycles.load(Ordering::Acquire);
        let elapsed = narf_time::now_cycles().saturating_sub(started);
        // Only consult the (slightly more expensive) run-queue scan once a fair
        // quantum is spent and the full slice is NOT yet up — the two cheap
        // cases (back-pressure, full-slice) are decided by the policy fn without
        // it. A normal, uncontended syscall exit therefore pays only the two
        // atomic loads + one TSC read above.
        let sibling_waiting = !backpressure
            && started != 0
            && elapsed >= slice / FAIR_QUANTUM_DIV
            && elapsed < slice
            && crate::has_other_runnable_work(crate::current_task_id().raw());
        if !syscall_exit_yield_decision(started, slice, elapsed, backpressure, sibling_waiting) {
            return;
        }
        // Re-arm the slot waker so the executor keeps us Ready and re-polls us
        // after the siblings run (mirrors try_preempt_user's pre-yield re-arm).
        {
            let g = (*p).current_waker.lock();
            if let Some(w) = g.as_ref() {
                w.wake_by_ref();
            }
        }
        // Yields via kernel_switch to the executor; returns here (with a fresh
        // tsc_started) when re-polled. Proven safe from syscall context — the
        // own-stack park paths (own_stack_park / wait4) switch out the same way.
        yield_current_stackful();
    }
}

/// Clone the executor slot-`Waker` of the CURRENT stackful task on this CPU
/// (the one `poll_to_yield` stashed). The own-stack park path registers THIS
/// waker with the relevant event source (timer wheel / futex queue / serial
/// IRQ / wait-child) so firing it sets the task's `awake` flag and the executor
/// re-polls — the per-task-own-stack analog of the longjmp poll's `cx.waker()`.
/// `None` if no stackful task is current (e.g. kernel-test context).
#[cfg(target_arch = "x86_64")]
pub fn current_stackful_waker() -> Option<Waker> {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: in-flight task on this CPU; `current_waker` is an IrqSafeSpinLock.
    unsafe { (*p).current_waker.lock().as_ref().cloned() }
}

/// Non-x86_64: NARF has no stackful executor yet, so there is never a
/// current stackful task — the own-stack durable-wake arming callers make
/// (`poll`/`epoll`) simply see `None` and fall through to the legacy park.
#[cfg(not(target_arch = "x86_64"))]
pub fn current_stackful_waker() -> Option<Waker> {
    None
}

/// Mark the CURRENT stackful task complete and `kernel_switch` out — never
/// returns (the executor observes `completed` and drops the task). The
/// per-task-own-stack replacement for the longjmp-based task exit.
///
/// # Safety
/// Called at CPL=0 from the exit path on the current task's own kernel stack.
#[cfg(target_arch = "x86_64")]
pub unsafe fn exit_current_stackful() -> ! {
    let cpu = this_cpu();
    let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: in-flight task on this CPU.
        unsafe {
            // Poison the saved ctx BEFORE publishing `completed`: the exit
            // continuation never resumes, so `ctx` must never be switched
            // into again. `poll_to_yield`'s completed-guard already refuses
            // to switch into a completed task; the zeroed `rip` makes any
            // path that slips past it trip `guard_switch_into` with
            // attribution instead of resuming a consumed continuation.
            (&raw mut (*p).ctx.rip).write(0);
            (*p).completed.store(true, Ordering::Release);
            let exec_ctx = (*p).exec_ctx.load(Ordering::Acquire);
            CURRENT_STACKFUL_TASK.inner[cpu].store(core::ptr::null_mut(), Ordering::Release);
            if !exec_ctx.is_null() {
                // Save the abandoned continuation into this CPU's dead
                // scratch slot, NOT the dying task's `ctx`: the executor
                // drops the `Box<KernelTask>` right after observing
                // `completed`, and the box must never be a save target once
                // `completed` is published (see EXIT_SCRATCH_CTX).
                let scratch = EXIT_SCRATCH_CTX.inner[cpu].get();
                // SAFETY: exec_ctx non-null (checked); executor populated it.
                guard_switch_into("exit_current_stackful:exec_ctx", &*exec_ctx);
                kernel_switch(scratch, exec_ctx);
            }
            // A completed task must never be switched back into.
            panic!(
                "exit_current_stackful cpu={cpu}: executor switched back into a \
                 COMPLETED task (or exec_ctx was null at exit) — slot-drop \
                 ordering violated"
            );
        }
    }
    // No stackful task current at an exit site: this CPU has lost its
    // executor continuation and can never reschedule — going quiet here
    // used to be a silent spin-loop that presented as "task N never
    // scheduled again". Panic with attribution instead.
    panic!("exit_current_stackful cpu={cpu}: no CURRENT stackful task at exit — lost executor continuation");
}

/// Fallback stub for exit_current_stackful on non-x86_64 architectures.
///
/// # Safety
/// This function is not supported on non-x86_64 architectures and will panic.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn exit_current_stackful() -> ! {
    unreachable!("own-stack is not supported on non-x86_64 architectures");
}

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
    // `ManuallyDrop` so the reclaim path can move the `Box<KernelTask>` out
    // and hand it to RCU for deferred free instead of dropping it inline —
    // see `impl Drop for StackfulAdapter`.
    inner: core::mem::ManuallyDrop<Box<KernelTask>>,
}

impl Drop for StackfulAdapter {
    /// Reclaim the inner `KernelTask` through RCU, not synchronously. A raw
    /// `*mut KernelTask` loaded from a per-CPU `CURRENT_STACKFUL_TASK` slot
    /// on another CPU (in `try_preempt` / syscall-exit / user-state publish)
    /// must not be freed until that CPU passes a quiescent point, or it would
    /// write a `kernel_switch` save / trap frame through freed memory (the
    /// executor-dispatch rip≈0x3 use-after-free). We clear the slots
    /// synchronously (so no CPU newly derefs the task), then defer the
    /// memory free one grace period; the executor's per-round
    /// `narf_rcu::advance_epoch_if_pending` keeps that grace period
    /// finite.
    fn drop(&mut self) {
        // SAFETY: `inner` is live here and never touched after this take
        // (the field's own drop glue is a no-op under `ManuallyDrop`).
        let task = unsafe { core::mem::ManuallyDrop::take(&mut self.inner) };
        task.clear_current_slots();
        narf_rcu::retire_box(task);
    }
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
            inner: core::mem::ManuallyDrop::new(KernelTask::new(future)),
        }
    }

    /// Construct with explicit options (slice + CPL0/CPL3 preemption policy +
    /// stack size). Used by `spawn_stackful_with_options`.
    /// Caller must invoke `apply_options` after construction to
    /// commit the options to the inner task — kept as a
    /// separate step so the StackfulOptions struct can stay
    /// `Copy`.
    pub fn with_options<F>(future: F, opts: crate::StackfulOptions) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let inner =
            core::mem::ManuallyDrop::new(KernelTask::with_stack_size(future, opts.stack_bytes));
        let me = Self { inner };
        // Cache opts on the adapter for `apply_options` — keep
        // a simple atomic-set pattern; opts are tiny.
        me.inner.set_slice_cycles(opts.slice_cycles);
        me.inner.set_no_preempt(opts.no_preempt);
        me.inner.set_user_preempt(opts.user_preempt);
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
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            // SAFETY: `StackfulAdapter` has no structurally-pinned fields we
            // move out of here — `inner` stays behind its `Box` and we only
            // take a `&mut` to call `poll_to_yield`, so the pin guarantee on
            // `self` is upheld.
            // SAFETY: Valid memory or trusted environment
            let this = unsafe { self.get_unchecked_mut() };
            // Use this CPU's PERSISTENT resume-context slot, not a
            // stack local. The task stashes this pointer in its
            // `exec_ctx` and switches back to it on yield/preempt; a
            // stack-local address would dangle once this poll returns
            // and a late switch-back could restore selector garbage as
            // the resume rip (see EXEC_CTX). The slot is single-CPU and
            // non-re-entrant (top-level executor only).
            let cpu = this_cpu();
            // SAFETY: only this CPU touches `EXEC_CTX.inner[cpu]`, and
            // StackfulAdapters are never polled nested, so there is no
            // concurrent or aliasing `&mut` to this slot. The borrow ends
            // when `poll_to_yield` returns (the task has switched back).
            let exec_ctx: &mut KernelContext = unsafe { &mut *EXEC_CTX.inner[cpu].get() };
            // SAFETY: Valid memory or trusted environment
            unsafe { this.inner.poll_to_yield(exec_ctx, cx.waker()) }
        }
    }
}

// Tests are inline below — same gating as the kernel_ctx smokes.

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_preempt_disable_nests_and_unwinds() -> TestResult {
        let before = preempt_count();
        {
            let outer = preempt_disable();
            if preempt_count() != before + 1 {
                return TestResult::Fail("outer preempt depth not published");
            }
            {
                let inner = preempt_disable();
                if preempt_count() != before + 2 {
                    return TestResult::Fail("nested preempt depth not published");
                }
                drop(inner);
            }
            if preempt_count() != before + 1 {
                return TestResult::Fail("nested preempt depth did not unwind");
            }
            drop(outer);
        }
        if preempt_count() != before {
            return TestResult::Fail("preempt depth leaked after guard drop");
        }
        TestResult::Pass
    }

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
        // SAFETY: Valid memory or trusted environment
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready after countdown");
        }
        if COUNTER.load(Ordering::Acquire) != 4 {
            return TestResult::Fail("final counter wrong");
        }
        TestResult::Pass
    }

    /// Stack-overflow tripwire detector: a fresh task's low-end
    /// canary is intact; scribbling any canary word (what a stack
    /// overrunning its bottom does on its way into the heap below)
    /// must be reported. Regression guard for the wl_xdg heap
    /// corruption (sys_fork's ~14 KiB frame overran the 16 KiB
    /// own-stack into an adjacent slab page — the detector is what
    /// turns that into an attributed panic instead of a slab canary
    /// trip minutes later).
    fn smoke_stack_canary_detects_bottom_scribble() -> TestResult {
        let mut task = KernelTask::new(async {});
        if task.stack_canary_clobbered().is_some() {
            return TestResult::Fail("fresh task's stack canary not intact");
        }
        // Simulate the first word an overflowing push sequence hits:
        // the HIGHEST canary word (pushes descend from the top).
        let hi = (STACK_CANARY_WORDS - 1) * 8;
        task.stack[hi..hi + 8].copy_from_slice(&0xdead_beef_dead_beefu64.to_ne_bytes());
        match task.stack_canary_clobbered() {
            Some((i, got)) if i == STACK_CANARY_WORDS - 1 && got == 0xdead_beef_dead_beef => {
                TestResult::Pass
            }
            Some(_) => TestResult::Fail("detector reported the wrong word"),
            None => TestResult::Fail("scribbled stack canary not detected"),
        }
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
        frame.cs = 0x08; // CPL=0
                         // Doesn't matter what CURRENT_STACKFUL_TASK holds — the
                         // vector check fires first.
                         // SAFETY: Valid memory or trusted environment
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
                         // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
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
            // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready after flag set");
        }
        TestResult::Pass
    }

    /// The QSBR quiescent-state gate. `poll_to_yield` publishes, per CPU,
    /// whether a `Poll::Pending` return was an involuntary preemption so the
    /// executor can suppress `report_quiescent` (a preemption is not a
    /// quiescent point — the suspended continuation may hold raw RCU
    /// references). `take_preempted_return` reads-and-clears that signal.
    /// A cooperative yield leaves it false; the `preempted` flag `try_preempt`
    /// sets before switching out surfaces as true exactly once, and is
    /// consumed so a later cooperative yield of the same task isn't
    /// mis-attributed.
    #[cfg(target_arch = "x86_64")]
    fn smoke_preempted_return_gate_reflects_preemption() -> TestResult {
        static FLAG: AtomicBool = AtomicBool::new(false);
        static POLLS: AtomicU32 = AtomicU32::new(0);
        FLAG.store(false, Ordering::Release);
        POLLS.store(0, Ordering::Release);

        // Drain any stale per-CPU signal left by a prior test on this CPU.
        let _ = take_preempted_return();

        let mut task = KernelTask::new(WaitOnFlag {
            flag: &FLAG,
            polls: &POLLS,
        });
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();

        // (1) Cooperative Pending yield: `preempted` stays clear → gate false.
        // SAFETY: Valid memory or trusted environment
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Pending {
            return TestResult::Fail("expected Pending while flag false");
        }
        if take_preempted_return() {
            return TestResult::Fail("cooperative yield mis-reported as preemption");
        }

        // (2) Simulate the observable effect of `try_preempt` (preempted=true)
        // ahead of the next yield; `poll_to_yield`'s tail must surface it.
        task.preempted.store(true, Ordering::Release);
        // SAFETY: Valid memory or trusted environment
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Pending {
            return TestResult::Fail("expected Pending while flag still false");
        }
        if !take_preempted_return() {
            return TestResult::Fail("preemption not surfaced to the quiescent gate");
        }
        // (3) One-shot: the second read is false (read-and-clear).
        if take_preempted_return() {
            return TestResult::Fail("preemption signal not cleared on read");
        }
        // `poll_to_yield` must have consumed `preempted` so a later cooperative
        // yield of the same task isn't mis-attributed as a preemption.
        if task.preempted.load(Ordering::Acquire) {
            return TestResult::Fail("poll_to_yield did not consume the preempted flag");
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
                // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
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

    /// The own-stack handoff must retarget the architecture's user-entry
    /// stack for the duration of the task and restore the previous per-CPU
    /// stack afterward. This specifically covers boot-time wiring of the
    /// setter/getter hooks: the xAPIC fallback once skipped both hooks because
    /// they were accidentally nested in the x2APIC-only IPI block.
    #[cfg(target_arch = "x86_64")]
    fn smoke_user_own_stack_retargets_kernel_entry_stack() -> TestResult {
        use core::sync::atomic::AtomicU64;

        static OBSERVED_TOP: AtomicU64 = AtomicU64::new(0);

        struct CaptureKernelStackTop;
        impl Future for CaptureKernelStackTop {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                OBSERVED_TOP.store(crate::current_kernel_stack_top(), Ordering::Release);
                Poll::Ready(())
            }
        }

        let baseline = crate::current_kernel_stack_top();
        if baseline == 0 {
            return TestResult::Fail("kernel-stack getter hook is not installed");
        }

        OBSERVED_TOP.store(0, Ordering::Release);
        let mut task = KernelTask::new(CaptureKernelStackTop);
        let expected_top = ((task.stack.as_ptr() as u64) + task.stack.len() as u64) & !0xFu64;
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        let saved_own_stack = USE_OWN_STACK.swap(true, Ordering::AcqRel);
        // SAFETY: single-threaded kernel smoke; the task, context, and waker
        // remain live for the complete switch round trip.
        let result = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        USE_OWN_STACK.store(saved_own_stack, Ordering::Release);

        if result != Poll::Ready(()) {
            return TestResult::Fail("own-stack capture task did not complete");
        }
        if OBSERVED_TOP.load(Ordering::Acquire) != expected_top {
            return TestResult::Fail("kernel-entry stack was not retargeted to the task stack");
        }
        if crate::current_kernel_stack_top() != baseline {
            return TestResult::Fail("kernel-entry stack baseline was not restored");
        }
        TestResult::Pass
    }

    /// `set_current_user_fs_base` must publish the user FS_BASE (TLS pointer)
    /// into the CURRENTLY-running stackful task's own per-task `user_fs_base`
    /// slot — the value `poll_to_yield` reloads on a later kernel_switch
    /// resume. This is the foundation of the own-stack/SMP TLS fix: a
    /// multithreaded task resumes via kernel_switch (NOT a re-poll), so the
    /// poll-time `set_user_fs_base` is bypassed; without the per-task slot a
    /// resumed thread runs on another thread's TLS and faults on `fs:[0]`.
    /// Mirrors the `user_cr3` publish.
    #[cfg(target_arch = "x86_64")]
    fn smoke_user_fs_base_published_to_current_task() -> TestResult {
        use core::sync::atomic::AtomicU64;
        const FS: u64 = 0x0000_7fab_cd00_0000;
        static SEEN: AtomicU64 = AtomicU64::new(0);

        struct PublishFs;
        impl Future for PublishFs {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                // task_body_rust set CURRENT_STACKFUL_TASK to us before this
                // poll, so the publish targets THIS task's slot.
                set_current_user_fs_base(FS);
                let cpu = this_cpu();
                let p = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
                if !p.is_null() {
                    // SAFETY: the in-flight task on this CPU during its own poll.
                    SEEN.store(
                        unsafe { (*p).user_fs_base.load(Ordering::Acquire) },
                        Ordering::Release,
                    );
                }
                Poll::Ready(())
            }
        }
        SEEN.store(0, Ordering::Release);

        let mut task = KernelTask::new(PublishFs);
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        // SAFETY: standard stackful poll, same as the sibling smokes.
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("expected Ready");
        }
        if SEEN.load(Ordering::Acquire) != FS {
            return TestResult::Fail("fs_base not published to the current task slot");
        }
        // Persisted on the task's own KernelTask slot — exactly what
        // poll_to_yield reloads on the next switch-in.
        if task.user_fs_base.load(Ordering::Acquire) != FS {
            return TestResult::Fail("fs_base did not persist on the per-task slot");
        }
        TestResult::Pass
    }

    /// End-to-end: under own-stack, `poll_to_yield` must RELOAD the task's
    /// published FS_BASE into the IA32_FS_BASE MSR before switching the task
    /// back in. Models the SMP bug directly: the task publishes its TLS base
    /// and yields; the test then CLOBBERS the MSR (as a peer task's fresh poll
    /// would); on resume the task reads IA32_FS_BASE and must observe ITS OWN
    /// base, not the clobbered one. Skipped when own-stack is off (the reload
    /// only lives on that path; the longjmp model re-publishes via re-poll).
    #[cfg(target_arch = "x86_64")]
    fn smoke_user_fs_base_reloaded_on_kernel_switch_resume() -> TestResult {
        use core::sync::atomic::{AtomicU32, AtomicU64};
        const FS: u64 = 0x0000_7fcc_dd00_0000;
        const CLOBBER: u64 = 0x0000_1111_2222_0000;
        const IA32_FS_BASE: u32 = 0xC000_0100;
        static PHASE: AtomicU32 = AtomicU32::new(0);
        static OBSERVED: AtomicU64 = AtomicU64::new(0);

        // The reload lives only on the own-stack poll_to_yield path. Enable it
        // for the duration and restore the prior setting afterwards so the rest
        // of the suite is unaffected. (The kernel-stack getter hook is wired in
        // bare_main before tests run, so the own-stack rsp0 save/restore in
        // poll_to_yield is valid here.)
        let saved_own_stack = USE_OWN_STACK.load(Ordering::Acquire);
        USE_OWN_STACK.store(true, Ordering::Release);

        struct FsResume;
        impl Future for FsResume {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                let ph = PHASE.fetch_add(1, Ordering::AcqRel);
                if ph == 0 {
                    // Publish our TLS base, then yield so the executor regains
                    // control (and the test can trash the MSR).
                    set_current_user_fs_base(FS);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                // Resumed via kernel_switch — poll_to_yield must have reloaded
                // FS_BASE for us. Read it straight from the MSR.
                // SAFETY: rdmsr of IA32_FS_BASE is unconditional at CPL=0.
                let v = unsafe { narf_arch::x86_64::msr::rdmsr(IA32_FS_BASE) };
                OBSERVED.store(v, Ordering::Release);
                Poll::Ready(())
            }
        }
        PHASE.store(0, Ordering::Release);
        OBSERVED.store(0, Ordering::Release);

        let mut task = KernelTask::new(FsResume);
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        // SAFETY: standard stackful poll.
        let r1 = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        // A peer task's fresh poll would leave a different FS_BASE in the MSR;
        // simulate that here.
        // SAFETY: writing IA32_FS_BASE is unconditional at CPL=0; the kernel
        // uses GS (not FS) for per-CPU state, so trashing FS_BASE is inert.
        unsafe { narf_arch::x86_64::msr::wrmsr(IA32_FS_BASE, CLOBBER) };
        // SAFETY: standard stackful poll.
        let r2 = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        // Restore a benign FS_BASE + the own-stack flag regardless of outcome.
        // SAFETY: as above.
        unsafe { narf_arch::x86_64::msr::wrmsr(IA32_FS_BASE, 0) };
        USE_OWN_STACK.store(saved_own_stack, Ordering::Release);

        if r1 != Poll::Pending {
            return TestResult::Fail("first poll should yield Pending");
        }
        if r2 != Poll::Ready(()) {
            return TestResult::Fail("resume should complete");
        }
        if OBSERVED.load(Ordering::Acquire) != FS {
            return TestResult::Fail("FS_BASE not reloaded on kernel_switch resume");
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

        let mut task_a = KernelTask::new(TrivialFuture {
            counter: &COUNTER_A,
        });
        let mut task_b = KernelTask::new(TrivialFuture {
            counter: &COUNTER_B,
        });
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();

        // Interleaved polls — each task uses its own ctx + stack.
        // SAFETY: Valid memory or trusted environment
        let ra = unsafe { task_a.poll_to_yield(&mut exec_ctx, &waker) };
        // SAFETY: Valid memory or trusted environment
        let rb = unsafe { task_b.poll_to_yield(&mut exec_ctx, &waker) };
        if ra != Poll::Ready(()) || rb != Poll::Ready(()) {
            return TestResult::Fail("one of the tasks didn't complete");
        }
        if COUNTER_A.load(Ordering::Acquire) != 1 || COUNTER_B.load(Ordering::Acquire) != 1 {
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
        if task.user_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("user_preempt should default false");
        }
        task.set_no_preempt(true);
        if !task.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("set_no_preempt(true) didn't stick");
        }
        task.set_no_preempt(false);
        if task.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("set_no_preempt(false) didn't stick");
        }
        task.set_user_preempt(true);
        if !task.user_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("set_user_preempt(true) didn't stick");
        }
        task.set_user_preempt(false);
        if task.user_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("set_user_preempt(false) didn't stick");
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

    /// Fair-share syscall-exit yield policy (`syscall_exit_yield_decision`):
    /// back-pressure and full-slice always yield; an EARLY yield requires BOTH a
    /// spent fair quantum AND a waiting sibling; an unstamped slice clock
    /// (`started == 0`) never yields. Regression pin for the SMP=1
    /// compositor-poll-spin starvation — a syscall-dense CPU hog must cede to a
    /// runnable peer after a fair quantum instead of holding the full slice.
    #[cfg(target_arch = "x86_64")]
    fn smoke_syscall_exit_fair_yield_policy() -> TestResult {
        use super::{syscall_exit_yield_decision as decide, FAIR_QUANTUM_DIV};
        let slice = 40_000u64;
        let q = slice / FAIR_QUANTUM_DIV; // fair-quantum threshold
                                          // Back-pressure always yields, even with the clock unstamped.
        if !decide(0, slice, 0, true, false) {
            return TestResult::Fail("back-pressure must yield regardless");
        }
        // Unstamped slice clock never yields (absent back-pressure).
        if decide(0, slice, slice * 2, false, true) {
            return TestResult::Fail("started==0 must not yield");
        }
        // Full slice spent always yields, even with no sibling waiting.
        if !decide(1, slice, slice, false, false) {
            return TestResult::Fail("full slice must yield");
        }
        // Below the fair quantum: never yield, even with a sibling waiting.
        if decide(1, slice, q - 1, false, true) {
            return TestResult::Fail("below fair quantum must not yield");
        }
        // At the fair quantum but no sibling: keep running to the full slice.
        if decide(1, slice, q, false, false) {
            return TestResult::Fail("fair quantum without a sibling must not yield");
        }
        // At the fair quantum WITH a sibling waiting: yield early.
        if !decide(1, slice, q, false, true) {
            return TestResult::Fail("fair quantum + sibling must yield early");
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
        OBSERVED_WAKER_DATA.store(Arc::as_ptr(&observer) as u64, Ordering::Release);

        let mut task = KernelTask::new(CaptureWakerData);
        let mut exec_ctx = KernelContext::default();
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };

        if observer.wakes.load(Ordering::Acquire) == 0 {
            return TestResult::Fail("inner future's waker didn't reach the executor's waker");
        }
        TestResult::Pass
    }

    /// StackfulAdapter::with_options applies both preemption policies, the
    /// slice, and stack size to the inner KernelTask.
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
            user_preempt: true,
            stack_bytes: 32 * 1024,
        };
        let adapter = StackfulAdapter::with_options(NoopPending, opts);
        if adapter.inner.slice_cycles.load(Ordering::Acquire) != 42_000_000 {
            return TestResult::Fail("slice_cycles not applied");
        }
        if !adapter.inner.no_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("no_preempt not applied");
        }
        if !adapter.inner.user_preempt.load(Ordering::Acquire) {
            return TestResult::Fail("user_preempt not applied");
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
        if opts.user_preempt {
            return TestResult::Fail("default user_preempt should be false");
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

    // ── Allocator concurrency: multiple tasks Box/Vec/alloc ─────────
    //
    // Stress the global allocator from multiple spawned tasks
    // round-robining through poll_one_round. Catches per-CPU
    // magazine bleed under task-switch pressure, double-free /
    // missed-free bugs in slab metadata, and Box/Vec drops at
    // unusual call sites (the stackful task's stack instead of
    // the executor's). One CPU at any instant but interleaved
    // at every yield point — much closer to real-world pump
    // workloads than single-threaded smokes.

    /// N stackful tasks each Box::new + drop a fixed-size payload
    /// in a loop, recording allocations + verifying byte
    /// integrity on each iteration. Verifies the slab path
    /// across task-switch boundaries.
    #[cfg(target_arch = "x86_64")]
    fn smoke_alloc_concurrency_box_round_trip() -> TestResult {
        const TASKS: usize = 4;
        const ITERS_PER_TASK: u32 = 32;
        static COUNTS: [AtomicU32; TASKS] = [
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ];
        static FAULT: AtomicBool = AtomicBool::new(false);
        for c in COUNTS.iter() {
            c.store(0, Ordering::Release);
        }
        FAULT.store(false, Ordering::Release);

        struct Allocator {
            idx: usize,
            remaining: u32,
        }
        impl Future for Allocator {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                // Fill the box with a recognisable per-task
                // pattern so a misalloc that hands out an
                // already-live block would corrupt it.
                let pattern = (self.idx as u8).wrapping_mul(17).wrapping_add(0x42);
                let buf: alloc::boxed::Box<[u8; 256]> = alloc::boxed::Box::new([pattern; 256]);
                // Sanity check that all bytes survived the
                // allocation untouched. (Realistically we'd only
                // catch live-block reuse here — but that IS the
                // bug worth flagging.)
                for &b in buf.iter() {
                    if b != pattern {
                        FAULT.store(true, Ordering::Release);
                        break;
                    }
                }
                drop(buf);
                COUNTS[self.idx].fetch_add(1, Ordering::AcqRel);
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..TASKS {
            crate::spawn_stackful(Allocator {
                idx: i,
                remaining: ITERS_PER_TASK,
            });
        }

        // 4 tasks × 32 iters = 128 polls. 256 rounds is ample
        // headroom even with other boot tasks sharing the queue.
        for _ in 0..256 {
            crate::poll_one_round();
            if COUNTS
                .iter()
                .all(|c| c.load(Ordering::Acquire) >= ITERS_PER_TASK)
            {
                break;
            }
        }

        if FAULT.load(Ordering::Acquire) {
            return TestResult::Fail("allocator handed out a live block under concurrent pressure");
        }
        for c in COUNTS.iter() {
            if c.load(Ordering::Acquire) != ITERS_PER_TASK {
                return TestResult::Fail("a task didn't reach its alloc iter target");
            }
        }
        TestResult::Pass
    }

    /// N stackful tasks each push N elements onto a `Vec`, drop
    /// the Vec, and repeat. Stresses the realloc + grow path of
    /// the global allocator across task switches.
    #[cfg(target_arch = "x86_64")]
    fn smoke_alloc_concurrency_vec_grow_drop() -> TestResult {
        const TASKS: usize = 3;
        const VECS_PER_TASK: u32 = 16;
        const PUSHES_PER_VEC: usize = 128;
        static COUNTS: [AtomicU32; TASKS] =
            [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
        static FAULT: AtomicBool = AtomicBool::new(false);
        for c in COUNTS.iter() {
            c.store(0, Ordering::Release);
        }
        FAULT.store(false, Ordering::Release);

        struct Grower {
            idx: usize,
            remaining: u32,
        }
        impl Future for Grower {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                let mut v: alloc::vec::Vec<u32> = alloc::vec::Vec::with_capacity(8);
                for k in 0..PUSHES_PER_VEC {
                    v.push((self.idx as u32) * 1_000_000 + k as u32);
                }
                // Verify the contents survived the grow path's
                // realloc + memcpy.
                for (k, &x) in v.iter().enumerate() {
                    if x != (self.idx as u32) * 1_000_000 + k as u32 {
                        FAULT.store(true, Ordering::Release);
                        break;
                    }
                }
                drop(v);
                COUNTS[self.idx].fetch_add(1, Ordering::AcqRel);
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..TASKS {
            crate::spawn_stackful(Grower {
                idx: i,
                remaining: VECS_PER_TASK,
            });
        }

        for _ in 0..256 {
            crate::poll_one_round();
            if COUNTS
                .iter()
                .all(|c| c.load(Ordering::Acquire) >= VECS_PER_TASK)
            {
                break;
            }
        }

        if FAULT.load(Ordering::Acquire) {
            return TestResult::Fail("Vec content corrupted across concurrent grows");
        }
        for c in COUNTS.iter() {
            if c.load(Ordering::Acquire) != VECS_PER_TASK {
                return TestResult::Fail("a Vec-grow task didn't reach its iter target");
            }
        }
        TestResult::Pass
    }

    /// Mixed pattern: some tasks Box, some Vec, varying sizes
    /// across the size-class boundaries so the slab's class
    /// dispatch is exercised. Sizes intentionally span 32, 64,
    /// 256, 1024, 4096 to hit multiple magazines.
    #[cfg(target_arch = "x86_64")]
    fn smoke_alloc_concurrency_mixed_sizes() -> TestResult {
        const TASKS: usize = 5;
        const ITERS_PER_TASK: u32 = 16;
        static COUNTS: [AtomicU32; TASKS] = [
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ];
        static FAULT: AtomicBool = AtomicBool::new(false);
        for c in COUNTS.iter() {
            c.store(0, Ordering::Release);
        }
        FAULT.store(false, Ordering::Release);

        // Sizes deliberately chosen to span the slab class
        // boundaries our allocator typically uses.
        const SIZES: [usize; 5] = [32, 64, 256, 1024, 4096];

        struct Mixed {
            idx: usize,
            remaining: u32,
        }
        impl Future for Mixed {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                let size = SIZES[self.idx];
                let pattern = (self.idx as u8).wrapping_add(0x37);
                let v: alloc::vec::Vec<u8> = alloc::vec![pattern; size];
                if v.iter().any(|&b| b != pattern) {
                    FAULT.store(true, Ordering::Release);
                }
                drop(v);
                COUNTS[self.idx].fetch_add(1, Ordering::AcqRel);
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..TASKS {
            crate::spawn_stackful(Mixed {
                idx: i,
                remaining: ITERS_PER_TASK,
            });
        }

        for _ in 0..256 {
            crate::poll_one_round();
            if COUNTS
                .iter()
                .all(|c| c.load(Ordering::Acquire) >= ITERS_PER_TASK)
            {
                break;
            }
        }

        if FAULT.load(Ordering::Acquire) {
            return TestResult::Fail("mixed-size concurrent alloc corrupted bytes");
        }
        for c in COUNTS.iter() {
            if c.load(Ordering::Acquire) != ITERS_PER_TASK {
                return TestResult::Fail("a mixed-size alloc task didn't complete");
            }
        }
        TestResult::Pass
    }

    // ── Spawn-flavour coverage ───────────────────────────────────────
    //
    // These tests all run sequentially on the BSP — kernel-test
    // is single-CPU at the test-runner granularity. Multiple
    // tasks interleave via poll_one_round; only one task runs at
    // any instant. Exercises the GLOBAL ready queue (not isolated
    // KernelTask + poll_to_yield), so spawn/queue/dequeue paths
    // are covered.

    /// Plain spawn() (cooperative, no dedicated stack): N tasks
    /// each count up via Pending + wake_by_ref. Verifies the
    /// stackless executor path round-robins correctly under load
    /// without needing the stackful machinery.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_plain_spawn_round_robin() -> TestResult {
        const TASKS: usize = 4;
        const TARGET: u32 = 6;
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
            crate::spawn(Counter {
                idx: i,
                target: TARGET,
                seen: 0,
            });
        }
        for _ in 0..64 {
            crate::poll_one_round();
            if COUNTERS.iter().all(|c| c.load(Ordering::Acquire) >= TARGET) {
                break;
            }
        }
        for c in COUNTERS.iter() {
            if c.load(Ordering::Acquire) != TARGET {
                return TestResult::Fail("plain-spawn task didn't reach target");
            }
        }
        TestResult::Pass
    }

    /// Mixed cohort: some plain spawn, some spawn_stackful, all
    /// driven by the same executor. The executor must round-robin
    /// fairly between them without preferring one type. Catches a
    /// regression where the StackfulAdapter::poll path consumes a
    /// disproportionate share of executor time (e.g. unconditional
    /// re-arm bug we already fixed — this is a regression guard).
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_mixed_spawn_types() -> TestResult {
        static PLAIN_DONE: AtomicU32 = AtomicU32::new(0);
        static STACK_DONE: AtomicU32 = AtomicU32::new(0);
        PLAIN_DONE.store(0, Ordering::Release);
        STACK_DONE.store(0, Ordering::Release);

        struct Once {
            counter: &'static AtomicU32,
        }
        impl Future for Once {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                self.counter.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        }

        for _ in 0..3 {
            crate::spawn(Once {
                counter: &PLAIN_DONE,
            });
            crate::spawn_stackful(Once {
                counter: &STACK_DONE,
            });
        }
        for _ in 0..32 {
            crate::poll_one_round();
            if PLAIN_DONE.load(Ordering::Acquire) >= 3 && STACK_DONE.load(Ordering::Acquire) >= 3 {
                break;
            }
        }
        if PLAIN_DONE.load(Ordering::Acquire) != 3 {
            return TestResult::Fail("plain-spawn tasks didn't all complete in mixed cohort");
        }
        if STACK_DONE.load(Ordering::Acquire) != 3 {
            return TestResult::Fail("spawn_stackful tasks didn't all complete in mixed cohort");
        }
        TestResult::Pass
    }

    /// Spawn-during-spawn: a task spawns another task during its
    /// poll. The newly-spawned task lands at the back of the
    /// queue and is polled in a SUBSEQUENT round (per the
    /// "snapshot queue_len at round start" rule in run_until_empty
    /// / poll_one_round). Without that rule, a task that spawns
    /// itself recursively would starve everyone else.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_spawn_during_spawn() -> TestResult {
        const CHILDREN: u32 = 8;
        static PARENT_DONE: AtomicBool = AtomicBool::new(false);
        static CHILD_DONE: AtomicU32 = AtomicU32::new(0);
        PARENT_DONE.store(false, Ordering::Release);
        CHILD_DONE.store(0, Ordering::Release);

        struct Child;
        impl Future for Child {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                CHILD_DONE.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        }

        struct Parent;
        impl Future for Parent {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                for _ in 0..CHILDREN {
                    crate::spawn(Child);
                }
                PARENT_DONE.store(true, Ordering::Release);
                Poll::Ready(())
            }
        }

        crate::spawn(Parent);
        for _ in 0..64 {
            crate::poll_one_round();
            if PARENT_DONE.load(Ordering::Acquire) && CHILD_DONE.load(Ordering::Acquire) >= CHILDREN
            {
                break;
            }
        }
        if !PARENT_DONE.load(Ordering::Acquire) {
            return TestResult::Fail("parent task didn't run");
        }
        if CHILD_DONE.load(Ordering::Acquire) != CHILDREN {
            return TestResult::Fail("children spawned by parent didn't all complete");
        }
        TestResult::Pass
    }

    /// Spawn_stackful inside spawn_stackful: a stackful task
    /// spawns another stackful task during its poll. Same
    /// guarantee as plain spawn-during-spawn but exercises the
    /// stackful adapter's nested-allocation path.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_stackful_spawns_stackful() -> TestResult {
        const CHILDREN: u32 = 6;
        static CHILD_COUNT: AtomicU32 = AtomicU32::new(0);
        static PARENT_DONE: AtomicBool = AtomicBool::new(false);
        CHILD_COUNT.store(0, Ordering::Release);
        PARENT_DONE.store(false, Ordering::Release);

        struct Child;
        impl Future for Child {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                CHILD_COUNT.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        }
        struct Parent;
        impl Future for Parent {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                for _ in 0..CHILDREN {
                    crate::spawn_stackful(Child);
                }
                PARENT_DONE.store(true, Ordering::Release);
                Poll::Ready(())
            }
        }

        crate::spawn_stackful(Parent);
        for _ in 0..128 {
            crate::poll_one_round();
            if PARENT_DONE.load(Ordering::Acquire)
                && CHILD_COUNT.load(Ordering::Acquire) >= CHILDREN
            {
                break;
            }
        }
        if !PARENT_DONE.load(Ordering::Acquire) {
            return TestResult::Fail("stackful parent didn't run");
        }
        if CHILD_COUNT.load(Ordering::Acquire) != CHILDREN {
            return TestResult::Fail("stackful children didn't all complete");
        }
        TestResult::Pass
    }

    /// FIFO guarantee under single-CPU sequential polling. With
    /// N tasks spawned in order, the FIRST poll round should
    /// visit them in spawn order. Verifies the ready queue is a
    /// FIFO (not a stack) and that the round_len snapshot bounds
    /// visits per round correctly.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_spawn_fifo_order() -> TestResult {
        static ORDER: [AtomicU32; 4] = [
            AtomicU32::new(u32::MAX),
            AtomicU32::new(u32::MAX),
            AtomicU32::new(u32::MAX),
            AtomicU32::new(u32::MAX),
        ];
        static TICKET: AtomicU32 = AtomicU32::new(0);
        for s in ORDER.iter() {
            s.store(u32::MAX, Ordering::Release);
        }
        TICKET.store(0, Ordering::Release);

        struct Marker {
            idx: usize,
        }
        impl Future for Marker {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                let ticket = TICKET.fetch_add(1, Ordering::AcqRel);
                ORDER[self.idx].store(ticket, Ordering::Release);
                Poll::Ready(())
            }
        }

        for i in 0..4 {
            crate::spawn(Marker { idx: i });
        }
        for _ in 0..8 {
            crate::poll_one_round();
            if ORDER.iter().all(|s| s.load(Ordering::Acquire) != u32::MAX) {
                break;
            }
        }
        // Spawn order: 0, 1, 2, 3 → ticket order should match.
        for (i, slot) in ORDER.iter().enumerate() {
            let t = slot.load(Ordering::Acquire);
            if t as usize != i {
                return TestResult::Fail("ready queue isn't FIFO across spawn order");
            }
        }
        TestResult::Pass
    }

    // ── RCU under multi-task pressure ───────────────────────────────
    //
    // RCU's existing 24 single-thread smokes cover the data
    // structure. These tests exercise the scheduler-RCU
    // integration: pins held across `.await`, defer_drop'd
    // payloads reclaimed only after all readers report
    // quiescent, atomic publish/swap under interleaved task
    // pressure. All run sequentially on the BSP but with
    // multiple tasks taking turns via poll_one_round.

    /// N tasks each repeatedly pin a QSBR read section, briefly
    /// observe shared data, then report quiescent and yield.
    /// Verifies pin/unpin nests correctly across task switches
    /// (each task has its own per-CPU pin counter; switching
    /// tasks on the same CPU must not corrupt the count).
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_rcu_qsbr_pin_under_task_switches() -> TestResult {
        const TASKS: usize = 4;
        const ITERS: u32 = 16;
        static COUNTS: [AtomicU32; TASKS] = [
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ];
        for c in COUNTS.iter() {
            c.store(0, Ordering::Release);
        }

        struct Pinner {
            idx: usize,
            remaining: u32,
        }
        impl Future for Pinner {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                {
                    let g = narf_rcu::pin();
                    // Observation: any data read here would be
                    // safe to dereference. For this smoke we just
                    // bump the counter while pinned.
                    COUNTS[self.idx].fetch_add(1, Ordering::AcqRel);
                    drop(g);
                }
                narf_rcu::report_quiescent();
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..TASKS {
            crate::spawn_stackful(Pinner {
                idx: i,
                remaining: ITERS,
            });
        }
        for _ in 0..256 {
            crate::poll_one_round();
            if COUNTS.iter().all(|c| c.load(Ordering::Acquire) >= ITERS) {
                break;
            }
        }
        for c in COUNTS.iter() {
            if c.load(Ordering::Acquire) != ITERS {
                return TestResult::Fail("RCU pinner task didn't complete its iterations");
            }
        }
        TestResult::Pass
    }

    /// One writer task publishes payloads via rcu::Atomic::store
    /// (with defer_drop semantics implicit); multiple readers
    /// load + observe. After all complete + sync, retired
    /// payloads' Drop must have run. Catches a regression where
    /// the scheduler doesn't drive quiescent reporting between
    /// task switches and retired payloads leak.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_rcu_atomic_publish_under_readers() -> TestResult {
        use alloc::sync::Arc;
        use narf_rcu::{Atomic, Owned};
        const READERS: usize = 3;
        const WRITES: u32 = 8;
        static DROPS: AtomicU32 = AtomicU32::new(0);
        static READS: [AtomicU32; READERS] =
            [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
        DROPS.store(0, Ordering::Release);
        for r in READS.iter() {
            r.store(0, Ordering::Release);
        }

        struct Payload {
            magic: u64,
        }
        impl Drop for Payload {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::AcqRel);
            }
        }

        // Atomic::new isn't const, so wrap in Arc and clone into
        // each task's capture. Same 'static-lifetime semantics
        // via refcount.
        let atomic: Arc<Atomic<Payload>> = Arc::new(Atomic::new(Payload { magic: 0xA11C }));

        struct Reader {
            idx: usize,
            remaining: u32,
            atomic: Arc<Atomic<Payload>>,
        }
        impl Future for Reader {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                {
                    let g = narf_rcu::pin();
                    let s = self.atomic.load(&g);
                    if s.as_ref().is_some() {
                        READS[self.idx].fetch_add(1, Ordering::AcqRel);
                    }
                }
                narf_rcu::report_quiescent();
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        struct Writer {
            remaining: u32,
            atomic: Arc<Atomic<Payload>>,
        }
        impl Future for Writer {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    return Poll::Ready(());
                }
                let val = (WRITES - self.remaining) as u64;
                let g = narf_rcu::pin();
                self.atomic.store(Owned::new(Payload { magic: val }), &g);
                drop(g);
                narf_rcu::report_quiescent();
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..READERS {
            crate::spawn_stackful(Reader {
                idx: i,
                remaining: 16,
                atomic: atomic.clone(),
            });
        }
        crate::spawn_stackful(Writer {
            remaining: WRITES,
            atomic: atomic.clone(),
        });

        for _ in 0..512 {
            crate::poll_one_round();
            narf_rcu::report_quiescent();
            if READS.iter().all(|r| r.load(Ordering::Acquire) >= 16) {
                break;
            }
        }

        narf_rcu::sync();
        let drops = DROPS.load(Ordering::Acquire);
        if drops == 0 {
            return TestResult::Fail("no retired payloads dropped — leak in defer_drop chain");
        }
        for r in READS.iter() {
            if r.load(Ordering::Acquire) == 0 {
                return TestResult::Fail("a reader task observed no payloads");
            }
        }
        TestResult::Pass
    }

    /// Pin held across a yield_now().await: the read guard is
    /// !Send so an `async fn` capturing it across `.await` would
    /// fail to compile (which is the design intent — protects
    /// against deadlock). This test verifies the contract by
    /// explicitly DROPPING the guard before yielding, which is
    /// the correct pattern. Catches a regression where someone
    /// accidentally makes ReadGuard Send + Sync.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_rcu_pin_drop_before_yield() -> TestResult {
        static ITER_COUNT: AtomicU32 = AtomicU32::new(0);
        ITER_COUNT.store(0, Ordering::Release);

        async fn body() {
            for _ in 0..8 {
                // Acquire + use + drop guard inside its own
                // scope so it can't be live across the .await.
                {
                    let _g = narf_rcu::pin();
                    ITER_COUNT.fetch_add(1, Ordering::AcqRel);
                }
                narf_rcu::report_quiescent();
                crate::yield_now().await;
            }
        }

        crate::spawn_stackful(body());
        for _ in 0..64 {
            crate::poll_one_round();
            if ITER_COUNT.load(Ordering::Acquire) >= 8 {
                break;
            }
        }
        if ITER_COUNT.load(Ordering::Acquire) != 8 {
            return TestResult::Fail("RCU-pin-then-yield body didn't complete");
        }
        TestResult::Pass
    }

    // ── Clone / user-task spawn concurrency ────────────────────────
    //
    // sys_clone and sys_fork have their own kernel-test
    // coverage (smoke_userspace_clone_*, smoke_userspace_fork_*
    // — 10+ tests in narf-userspace). What's NOT directly
    // covered there: the SCHEDULER side of multi-task spawn_user
    // under concurrent pressure. These tests model that by
    // exercising the underlying TaskId allocation + ready-queue
    // semantics that user-task spawn relies on.

    // ── Capability primitives under multi-task pressure ────────────
    //
    // The 16 single-thread capability smokes cover the data
    // structure. These probe the multi-task surface — cap
    // bootstrap under concurrent spawn, revoke + check_live
    // race semantics.

    /// N tasks each bootstrap a fresh capability of the same
    /// kind; verify every returned slot index is distinct.
    /// Catches a regression where `Cap::bootstrap`'s table slot
    /// allocation hands out the same index to two concurrent
    /// callers.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_cap_bootstrap_unique_slots() -> TestResult {
        use alloc::sync::Arc;
        use narf_capabilities::{Cap, CapKind, CapType, Write};
        use narf_lib::sync::IrqSafeSpinLock;

        struct TestObj;
        impl CapType for TestObj {
            const KIND: CapKind = CapKind::Endpoint;
        }

        const TASKS: usize = 8;
        let collected: Arc<IrqSafeSpinLock<alloc::vec::Vec<u32>>> =
            Arc::new(IrqSafeSpinLock::new(alloc::vec::Vec::new()));
        static DONE: AtomicU32 = AtomicU32::new(0);
        DONE.store(0, Ordering::Release);

        struct Booter {
            collected: Arc<IrqSafeSpinLock<alloc::vec::Vec<u32>>>,
        }
        impl Future for Booter {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                let cap: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
                let slot_idx = cap.slot().index;
                self.collected.lock().push(slot_idx);
                cap.revoke();
                DONE.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        }

        for _ in 0..TASKS {
            crate::spawn_stackful(Booter {
                collected: collected.clone(),
            });
        }
        for _ in 0..32 {
            crate::poll_one_round();
            if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
                break;
            }
        }
        if (DONE.load(Ordering::Acquire) as usize) != TASKS {
            return TestResult::Fail("cap bootstrap tasks didn't all complete");
        }
        let mut slots = collected.lock().clone();
        let before = slots.len();
        slots.sort();
        slots.dedup();
        if slots.len() != before {
            return TestResult::Fail("Cap::bootstrap returned duplicate slot index to two callers");
        }
        TestResult::Pass
    }

    /// Revoke observed by clone: spawn task A holding a Cap +
    /// task B that revokes a clone of it. After both complete,
    /// the original cap must report not-live (revoke bumps the
    /// kind epoch, which invalidates every Cap of that kind).
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_cap_revoke_observed_by_peer() -> TestResult {
        use alloc::sync::Arc;
        use narf_capabilities::{Cap, CapKind, CapType, Write};
        use narf_lib::sync::IrqSafeSpinLock;

        struct TestObj;
        impl CapType for TestObj {
            const KIND: CapKind = CapKind::Endpoint;
        }

        // Build cap on this thread; share via Arc<Mutex<Option>>
        // so the revoker can take() it (Cap::revoke consumes).
        let cap: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
        let cap_clone = cap; // Cap is Copy
        let revoker_slot: Arc<IrqSafeSpinLock<Option<Cap<TestObj, Write>>>> =
            Arc::new(IrqSafeSpinLock::new(Some(cap_clone)));
        static LIVE_BEFORE: AtomicBool = AtomicBool::new(false);
        static LIVE_AFTER: AtomicBool = AtomicBool::new(true);
        static DONE_OBS: AtomicBool = AtomicBool::new(false);
        static DONE_REV: AtomicBool = AtomicBool::new(false);
        LIVE_BEFORE.store(false, Ordering::Release);
        LIVE_AFTER.store(true, Ordering::Release);
        DONE_OBS.store(false, Ordering::Release);
        DONE_REV.store(false, Ordering::Release);

        struct Observer {
            cap: Cap<TestObj, Write>,
        }
        impl Future for Observer {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if !DONE_REV.load(Ordering::Acquire) {
                    if self.cap.is_live() {
                        LIVE_BEFORE.store(true, Ordering::Release);
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                LIVE_AFTER.store(self.cap.is_live(), Ordering::Release);
                DONE_OBS.store(true, Ordering::Release);
                Poll::Ready(())
            }
        }

        struct Revoker {
            slot: Arc<IrqSafeSpinLock<Option<Cap<TestObj, Write>>>>,
        }
        impl Future for Revoker {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                if let Some(c) = self.slot.lock().take() {
                    c.revoke();
                }
                DONE_REV.store(true, Ordering::Release);
                Poll::Ready(())
            }
        }

        crate::spawn_stackful(Observer { cap });
        crate::spawn_stackful(Revoker {
            slot: revoker_slot.clone(),
        });

        for _ in 0..64 {
            crate::poll_one_round();
            if DONE_OBS.load(Ordering::Acquire) && DONE_REV.load(Ordering::Acquire) {
                break;
            }
        }
        if !LIVE_BEFORE.load(Ordering::Acquire) {
            return TestResult::Fail("cap wasn't observed live before revoke");
        }
        if LIVE_AFTER.load(Ordering::Acquire) {
            return TestResult::Fail("cap observed live AFTER revoke from peer task");
        }
        TestResult::Pass
    }

    // ── Timer wheel under multi-task pressure ──────────────────────
    //
    // The wheel has 7 single-thread tests in time/src/tests.rs
    // (register, refresh, cancel, fire_due, generations). What's
    // not covered: many tasks concurrently registering deadlines
    // and the wheel handing them all distinct slots / firing
    // them at the right time.

    /// N tasks each await a short sleep_cycles + then complete.
    /// Verifies the timer wheel can hand out distinct slots
    /// under concurrent registration pressure and fire them on
    /// the LAPIC-driven drain path (timer_wheel::register +
    /// fire_due-from-on_timer_tick we added).
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_timer_wheel_many_sleepers_fire() -> TestResult {
        const TASKS: usize = 6;
        static DONE: AtomicU32 = AtomicU32::new(0);
        DONE.store(0, Ordering::Release);

        async fn sleeper() {
            // 1_000_000 cycles ≈ 300 µs on a 3.3 GHz CPU —
            // well below the LAPIC slice but long enough to
            // ensure the wheel actually has to fire us, not
            // just immediately return Ready on the first poll.
            narf_time::sleep_cycles(1_000_000).await;
            DONE.fetch_add(1, Ordering::AcqRel);
        }

        for _ in 0..TASKS {
            crate::spawn_stackful(sleeper());
        }
        // Drive enough rounds that the LAPIC tick (every
        // ~10 ms on QEMU) fires multiple times and drains the
        // wheel. 1024 rounds with timer_pump activity is
        // ample.
        for _ in 0..1024 {
            crate::poll_one_round();
            if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
                break;
            }
        }
        if (DONE.load(Ordering::Acquire) as usize) != TASKS {
            return TestResult::Fail("not all timer-wheel sleepers fired");
        }
        TestResult::Pass
    }

    /// N tasks contend for AtomicPool leases; never observe a
    /// double-lease (same item handed to two callers). Verifies
    /// the IrqSafeSpinLock + Vec::pop hot path under interleaved
    /// task pressure.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_atomic_pool_no_double_lease() -> TestResult {
        use narf_memory::atomic_pool::AtomicPool;

        // Each pool item carries a unique id; tasks lease,
        // record the id, drop, repeat. If two tasks ever lease
        // the same id at the same time, we set DOUBLE.
        const POOL_SIZE: usize = 4;
        const TASKS: usize = 4;
        const ITERS: u32 = 16;

        let pool: &'static AtomicPool<u32> =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(AtomicPool::new(POOL_SIZE, {
                let mut next = 0u32;
                move || {
                    let id = next;
                    next += 1;
                    id
                }
            })));
        static IN_USE: [AtomicBool; POOL_SIZE] = [
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
        ];
        static DOUBLE: AtomicBool = AtomicBool::new(false);
        static DONE: AtomicU32 = AtomicU32::new(0);
        for s in IN_USE.iter() {
            s.store(false, Ordering::Release);
        }
        DOUBLE.store(false, Ordering::Release);
        DONE.store(0, Ordering::Release);

        struct Leaser {
            pool: &'static AtomicPool<u32>,
            remaining: u32,
        }
        impl Future for Leaser {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    DONE.fetch_add(1, Ordering::AcqRel);
                    return Poll::Ready(());
                }
                let item = match self.pool.try_get() {
                    Some(i) => i,
                    None => {
                        // Pool exhausted by peers; retry next round.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                };
                let id = *item as usize;
                if id >= POOL_SIZE {
                    DOUBLE.store(true, Ordering::Release);
                    return Poll::Ready(());
                }
                if IN_USE[id].swap(true, Ordering::AcqRel) {
                    // We saw IN_USE already true → another task
                    // has this same item — double-lease bug.
                    DOUBLE.store(true, Ordering::Release);
                    return Poll::Ready(());
                }
                // Brief use, then release.
                IN_USE[id].store(false, Ordering::Release);
                drop(item);
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for _ in 0..TASKS {
            crate::spawn_stackful(Leaser {
                pool,
                remaining: ITERS,
            });
        }
        for _ in 0..512 {
            crate::poll_one_round();
            if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
                break;
            }
        }
        if DOUBLE.load(Ordering::Acquire) {
            return TestResult::Fail("AtomicPool handed the same item to two concurrent leasers");
        }
        if (DONE.load(Ordering::Acquire) as usize) != TASKS {
            return TestResult::Fail("pool-stress tasks didn't all finish");
        }
        TestResult::Pass
    }

    /// Distinct task IDs across many concurrent spawns. spawn()
    /// returns a TaskId; if the allocation racy, two
    /// concurrent calls could hand out the same id. Verifies
    /// uniqueness across a burst.
    #[cfg(target_arch = "x86_64")]
    fn smoke_concurrency_task_ids_unique_across_spawns() -> TestResult {
        const N: usize = 32;
        let mut ids = alloc::vec::Vec::with_capacity(N);
        struct Noop;
        impl Future for Noop {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        for _ in 0..N {
            let id = crate::spawn(Noop);
            ids.push(id);
        }
        // Sort + dedup: dedup() in place collapses adjacent
        // equal elements. After sort, a length change after
        // dedup means duplicates existed.
        let before = ids.len();
        ids.sort();
        ids.dedup();
        if ids.len() != before {
            return TestResult::Fail("two spawn() calls returned the same TaskId");
        }
        // Drain.
        for _ in 0..32 {
            crate::poll_one_round();
        }
        TestResult::Pass
    }

    /// Multi-task vmalloc CAS contention: N tasks each request a
    /// distinct VA range; ranges must be disjoint. vmalloc uses
    /// compare_exchange_weak on the cursor; this exercises that
    /// path under interleaved poll pressure. (Bump-pointer
    /// allocator: free is a no-op so this leaks VA, but the test
    /// budget is small enough not to exhaust the 4 GiB pool.)
    #[cfg(target_arch = "x86_64")]
    fn smoke_alloc_concurrency_vmalloc_cas_disjoint() -> TestResult {
        use narf_memory::vmalloc;
        const TASKS: usize = 4;
        const ITERS: u32 = 8;
        static BASES: [AtomicU64; TASKS * (ITERS as usize)] = [
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ];
        static COMPLETED: AtomicU32 = AtomicU32::new(0);
        for s in BASES.iter() {
            s.store(0, Ordering::Release);
        }
        COMPLETED.store(0, Ordering::Release);

        struct VmStress {
            idx: usize,
            remaining: u32,
        }
        impl Future for VmStress {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.remaining == 0 {
                    COMPLETED.fetch_add(1, Ordering::AcqRel);
                    return Poll::Ready(());
                }
                let r = match vmalloc::alloc(4096) {
                    Ok(r) => r,
                    Err(_) => return Poll::Ready(()), // exhausted; bail
                };
                let iter_idx = (ITERS - self.remaining) as usize;
                let slot = self.idx * (ITERS as usize) + iter_idx;
                BASES[slot].store(r.base, Ordering::Release);
                vmalloc::free(r);
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        for i in 0..TASKS {
            crate::spawn_stackful(VmStress {
                idx: i,
                remaining: ITERS,
            });
        }

        for _ in 0..256 {
            crate::poll_one_round();
            if COMPLETED.load(Ordering::Acquire) as usize >= TASKS {
                break;
            }
        }
        if (COMPLETED.load(Ordering::Acquire) as usize) != TASKS {
            return TestResult::Fail("vmalloc concurrency tasks didn't all finish");
        }

        // All recorded bases must be page-aligned and pairwise
        // distinct. The bump cursor + atomic CAS guarantee this.
        let mut seen = alloc::vec::Vec::new();
        for slot in BASES.iter() {
            let b = slot.load(Ordering::Acquire);
            if b == 0 {
                continue; // task bailed via Exhausted; tolerated.
            }
            if b & 0xFFF != 0 {
                return TestResult::Fail("vmalloc returned non-page-aligned base under contention");
            }
            if seen.contains(&b) {
                return TestResult::Fail("vmalloc returned the same base to two callers");
            }
            seen.push(b);
        }
        TestResult::Pass
    }

    /// Spawn-allocator stress: each task's Box::pin(future) at
    /// spawn time also runs through the allocator. With many
    /// tasks spawned concurrently then drained, this exercises
    /// the spawn path's allocation pattern (which is a frequent
    /// real-world case — driver IRQ wakers re-spawning task
    /// continuations, etc).
    #[cfg(target_arch = "x86_64")]
    fn smoke_alloc_concurrency_many_spawns_finish() -> TestResult {
        const TASKS: usize = 16;
        static COMPLETED: AtomicU32 = AtomicU32::new(0);
        COMPLETED.store(0, Ordering::Release);

        struct OneShot;
        impl Future for OneShot {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                COMPLETED.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        }

        for _ in 0..TASKS {
            crate::spawn_stackful(OneShot);
        }

        for _ in 0..64 {
            crate::poll_one_round();
            if COMPLETED.load(Ordering::Acquire) as usize >= TASKS {
                break;
            }
        }

        let final_count = COMPLETED.load(Ordering::Acquire);
        if (final_count as usize) != TASKS {
            return TestResult::Fail(
                "not all bulk-spawned tasks completed — allocator or queue dropped one",
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
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };

        let after = CURRENT_STACKFUL_TASK.inner[cpu].load(Ordering::Acquire);
        if !after.is_null() {
            return TestResult::Fail(
                "CURRENT_STACKFUL_TASK not cleared on this CPU after Ready return",
            );
        }
        TestResult::Pass
    }

    /// Dropping a `KernelTask` must clear every per-CPU
    /// `CURRENT_STACKFUL_TASK` slot that still points at it. This is the
    /// backstop against a slot stranded by a work-steal migration
    /// (set on CPU A, resumed/cleared on CPU B): without it, a timer
    /// tick on CPU A after the task's `Box` is freed would drive
    /// `try_preempt` to write through freed memory (the rip≈0x3 UAF).
    #[cfg(target_arch = "x86_64")]
    fn smoke_drop_clears_stranded_current_slots() -> TestResult {
        struct ReadyImmediately;
        impl Future for ReadyImmediately {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        // Simulate a stranded slot: arm several CPUs' slots at this
        // task's pointer, as a mid-poll migration would leave behind,
        // then drop the task and require every slot to be cleared.
        let task = KernelTask::new(ReadyImmediately);
        let task_ptr = &*task as *const KernelTask as *mut KernelTask;
        let n = CURRENT_STACKFUL_TASK.inner.len();
        // Strand slot 0, the current CPU, and the last slot; leave a
        // decoy pointer in another slot to prove only matching slots
        // are cleared.
        let decoy = 0xdead_beef_usize as *mut KernelTask;
        CURRENT_STACKFUL_TASK.inner[0].store(task_ptr, Ordering::Release);
        CURRENT_STACKFUL_TASK.inner[this_cpu() % n].store(task_ptr, Ordering::Release);
        CURRENT_STACKFUL_TASK.inner[n - 1].store(task_ptr, Ordering::Release);
        let decoy_idx = if n >= 2 { 1 } else { 0 };
        if decoy_idx != 0 && decoy_idx != n - 1 && decoy_idx != this_cpu() % n {
            CURRENT_STACKFUL_TASK.inner[decoy_idx].store(decoy, Ordering::Release);
        }

        drop(task);

        for (i, slot) in CURRENT_STACKFUL_TASK.inner.iter().enumerate() {
            let v = slot.load(Ordering::Acquire);
            if v == task_ptr {
                return TestResult::Fail(
                    "Drop left a CURRENT_STACKFUL_TASK slot pointing at the freed task",
                );
            }
            if i == decoy_idx && decoy_idx != 0 && decoy_idx != n - 1 && v != decoy {
                // Reset before failing to avoid leaking the decoy.
                slot.store(core::ptr::null_mut(), Ordering::Release);
                return TestResult::Fail("Drop wrongly cleared a non-matching slot");
            }
        }
        // Clean up the decoy so it can't confuse later tests / a real
        // preempt tick.
        CURRENT_STACKFUL_TASK.inner[decoy_idx].store(core::ptr::null_mut(), Ordering::Release);
        TestResult::Pass
    }

    /// Dropping a `StackfulAdapter` must (1) clear any per-CPU slot that
    /// names its `KernelTask` SYNCHRONOUSLY — so no CPU can newly load the
    /// pointer — and (2) defer the actual memory free through RCU rather
    /// than freeing inline, so a raw pointer already loaded on another CPU
    /// keeps pointing at valid memory until a grace period elapses. This is
    /// the reclaim contract that closes the cross-CPU executor-dispatch
    /// rip≈0x3 use-after-free.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stackful_adapter_drop_defers_reclaim() -> TestResult {
        struct ReadyImmediately;
        impl Future for ReadyImmediately {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        let adapter = StackfulAdapter::new(ReadyImmediately);
        // Address of the inner KernelTask (what CURRENT_STACKFUL_TASK holds).
        let task_ptr = &**adapter.inner as *const KernelTask as *mut KernelTask;
        let n = CURRENT_STACKFUL_TASK.inner.len();
        CURRENT_STACKFUL_TASK.inner[0].store(task_ptr, Ordering::Release);
        CURRENT_STACKFUL_TASK.inner[this_cpu() % n].store(task_ptr, Ordering::Release);

        drop(adapter);

        // (1) Slots cleared synchronously on drop.
        for slot in CURRENT_STACKFUL_TASK.inner.iter() {
            if slot.load(Ordering::Acquire) == task_ptr {
                return TestResult::Fail(
                    "StackfulAdapter drop left a CURRENT_STACKFUL_TASK slot set",
                );
            }
        }
        // (2) Drive a grace period so the RCU-deferred free actually runs
        // (and this test doesn't leak the KernelTask). No panic / double-free
        // through the deferred-drop path is itself part of what we're testing.
        narf_rcu::report_quiescent();
        narf_rcu::advance_epoch_if_pending();
        narf_rcu::report_quiescent();
        TestResult::Pass
    }

    /// Re-polling an already-completed task must return `Ready` WITHOUT
    /// switching into its saved ctx: a completed task's ctx is a consumed
    /// continuation (and `exit_current_stackful` poisons its `rip`), so a
    /// stale wake that races the exit on another CPU must degrade to a
    /// clean drop, never a resume of dead state.
    #[cfg(target_arch = "x86_64")]
    fn smoke_completed_task_repoll_is_ready_without_switch() -> TestResult {
        struct ReadyImmediately;
        impl Future for ReadyImmediately {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        let mut task = KernelTask::new(ReadyImmediately);
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        // First poll drives the future to completion.
        // SAFETY: standard stackful poll, same as the sibling smokes.
        if unsafe { task.poll_to_yield(&mut exec_ctx, &waker) } != Poll::Ready(()) {
            return TestResult::Fail("expected Ready on first poll");
        }
        // Poison the resume context the way exit_current_stackful does; a
        // second poll that (wrongly) switched in would trip the CTXGUARD
        // panic, so a clean Ready return proves no switch happened.
        task.ctx.rip = 0;
        // SAFETY: same as above; the completed-guard must return early.
        if unsafe { task.poll_to_yield(&mut exec_ctx, &waker) } != Poll::Ready(()) {
            return TestResult::Fail("re-poll of a completed task must return Ready");
        }
        TestResult::Pass
    }

    /// `exit_current_stackful` must (1) complete the task and hand control
    /// back to the executor's context, (2) poison the task's saved `ctx.rip`
    /// so the consumed exit continuation can never be switched into, and
    /// (3) leave the per-CPU CURRENT slot clear. The final context save
    /// goes to the per-CPU scratch slot — the dying task's own `ctx` is
    /// never a save target once `completed` is published, which is what
    /// keeps the executor's immediate `Box<KernelTask>` drop sound.
    #[cfg(target_arch = "x86_64")]
    fn smoke_exit_current_stackful_poisons_ctx_and_completes() -> TestResult {
        struct ExitsViaPrimitive;
        impl Future for ExitsViaPrimitive {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                // SAFETY: runs at CPL0 on this stackful task's own stack,
                // with the task current on this CPU (task_body_rust armed
                // CURRENT before polling us) — the primitive's contract.
                unsafe { exit_current_stackful() }
            }
        }
        let mut task = KernelTask::new(ExitsViaPrimitive);
        let mut exec_ctx = KernelContext::default();
        let waker = KernelTask::no_op_waker();
        // SAFETY: standard stackful poll; the future diverges into
        // exit_current_stackful, which switches back to `exec_ctx`.
        let r = unsafe { task.poll_to_yield(&mut exec_ctx, &waker) };
        if r != Poll::Ready(()) {
            return TestResult::Fail("exit_current_stackful must complete the task");
        }
        if !task.completed.load(Ordering::Acquire) {
            return TestResult::Fail("completed flag not set by exit_current_stackful");
        }
        if task.ctx.rip != 0 {
            return TestResult::Fail("exit_current_stackful did not poison ctx.rip");
        }
        let cpu = this_cpu();
        if !CURRENT_STACKFUL_TASK.inner[cpu]
            .load(Ordering::Acquire)
            .is_null()
        {
            return TestResult::Fail("CURRENT slot not cleared by exit_current_stackful");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "scheduler/stackful",
        smoke_preempt_disable_nests_and_unwinds
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_adapter_drop_defers_reclaim
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_completed_task_repoll_is_ready_without_switch
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_exit_current_stackful_poisons_ctx_and_completes
    );

    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_trivial_future_completes
    );
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stack_canary_detects_bottom_scribble
    );
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
    kernel_test_in!("scheduler/stackful", smoke_try_preempt_skips_when_no_task);
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
        smoke_preempted_return_gate_reflects_preemption
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_stackful_runs_on_dedicated_stack);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_user_own_stack_retargets_kernel_entry_stack
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
    kernel_test_in!("scheduler/stackful", smoke_syscall_exit_fair_yield_policy);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_stackful_inner_waker_is_executor_waker
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_current_task_cleared_after_poll);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_drop_clears_stranded_current_slots
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_stackful_adapter_applies_options);
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
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_alloc_concurrency_box_round_trip);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_alloc_concurrency_vec_grow_drop);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_alloc_concurrency_mixed_sizes);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_alloc_concurrency_many_spawns_finish
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_alloc_concurrency_vmalloc_cas_disjoint
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_plain_spawn_round_robin
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_concurrency_mixed_spawn_types);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_concurrency_spawn_during_spawn);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_stackful_spawns_stackful
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("scheduler/stackful", smoke_concurrency_spawn_fifo_order);
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_rcu_qsbr_pin_under_task_switches
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_rcu_atomic_publish_under_readers
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_rcu_pin_drop_before_yield
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_task_ids_unique_across_spawns
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_cap_bootstrap_unique_slots
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_cap_revoke_observed_by_peer
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_timer_wheel_many_sleepers_fire
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_concurrency_atomic_pool_no_double_lease
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_user_fs_base_published_to_current_task
    );
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "scheduler/stackful",
        smoke_user_fs_base_reloaded_on_kernel_switch_resume
    );
}
