//! Kernel context-switch primitive for stackful tasks.
//!
//! Spec: `scheduler/specification/preemption.md` Phase 1.
//!
//! Provides the foundation for preemptive kernel-task scheduling:
//! each spawned async task gets its own kernel stack, and the
//! executor switches between tasks via a register save/restore
//! pair. Builds on the existing `setjmp`/`longjmp` machinery used
//! for S3 resume + user-task re-entry, but takes both contexts
//! explicitly so the executor can do a true swap in one call.
//!
//! ## Layout
//!
//! `KernelContext` is 64 bytes, 16-byte aligned, holding the
//! callee-saved GPRs (SysV-AMD64) + RSP + saved RIP. Byte offsets
//! are load-bearing — the naked asm reads/writes by offset:
//!
//! ```text
//!   offset  field
//!   ------  -----
//!     0     rbx
//!     8     rbp
//!    16     r12
//!    24     r13
//!    32     r14
//!    40     r15
//!    48     rsp
//!    56     rip
//! ```
//!
//! Caller-saved GPRs (rax, rcx, rdx, rsi, rdi, r8-r11) are NOT
//! saved — the C calling convention says the caller must not
//! expect those preserved across a function call, and
//! `kernel_switch` is an `extern "C"` function. The same rule
//! lets us clobber rcx/rax inside the asm without saving.
//!
//! XMM/YMM/ZMM registers: kernel-side Rust code uses softfloat
//! (no `-C target-feature=+sse` for `narf-frame`'s
//! `x86_64-unknown-none` target), so no FP/SIMD state to save.
//! If the kernel ever uses SSE/AVX, `kernel_switch` would extend
//! to xsave/xrstor.
//!
//! ## Usage shape
//!
//! ```ignore
//! let mut executor_ctx = KernelContext::default();
//! // ... task setup: allocate stack, set task_ctx.rsp = stack top,
//! //                 task_ctx.rip = task entry trampoline ...
//! unsafe { kernel_switch(&mut executor_ctx, &task_ctx); }
//! // We "return" here when the task switches back via another
//! // kernel_switch call with our executor_ctx as the destination.
//! ```
//!
//! Both halves share the *same* primitive — the executor and each
//! task store their own `KernelContext`, and either side calls
//! `kernel_switch(&mut my_ctx, &peer_ctx)` to hand control over.
//! No asymmetry; the "side currently running" is determined by
//! whose stack/RIP/GPRs are loaded.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::arch::naked_asm;

/// 64-byte, 16-aligned kernel-task register snapshot. Layout is
/// fixed for the naked asm in `kernel_switch`.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct KernelContext {
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Stack pointer. For a fresh task, set to (stack top) so the
    /// first `kernel_switch` lands on a known-good stack. For a
    /// task being preserved across yields, this holds whatever rsp
    /// was at the yield-time call to `kernel_switch`.
    pub rsp: u64,
    /// Instruction to resume at. For a fresh task, set to a
    /// trampoline entry that picks up `r15` (or stack-passed args)
    /// and calls the task body. For a yielded task, this is the
    /// instruction just after its `kernel_switch` call.
    pub rip: u64,
    /// Saved RFLAGS state. Only IF (bit 9) is functionally
    /// restored — kernel_switch uses sti/cli based on its value
    /// before the final jmp. Other rflags bits are caller-saved
    /// per SysV (volatile across the call boundary). Critical for
    /// preempt-from-trap: when a stackful task is preempted out
    /// of an IF=0 trap-handler context, the executor switched-into
    /// must resume with IF=1. Without this, the executor would
    /// run with IF=0 — no timer ticks, no IRQ delivery, the kernel
    /// hangs even though it's not in any specific wait.
    pub rflags: u64,
}

impl KernelContext {
    /// Initialize a context for a fresh task: rip = entry, rsp =
    /// stack_top, r15 = arg (a `*mut KernelTask`-style raw ptr the
    /// trampoline pulls out). Stack must be at least 16-byte aligned.
    /// The first `kernel_switch` into this context will land the
    /// CPU at `entry` with `rsp = stack_top` and `r15 = arg`.
    /// RFLAGS is initialised to IF=1 + reserved bit 1 so a freshly
    /// resumed task runs with interrupts enabled.
    pub fn fresh(stack_top: u64, entry: u64, arg: u64) -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: arg,
            rsp: stack_top,
            rip: entry,
            // IF=1 (bit 9) + reserved bit 1.
            rflags: 0x202,
        }
    }
}

/// Save the current execution state into `*out` and resume from
/// `*incoming`. The "return" from this fn happens on the
/// incoming context's stack at its saved RIP.
///
/// On the OUT side: from the caller's POV, control passes to the
/// peer context. The next time *some other* `kernel_switch` call
/// targets this `*out` context, control returns here — `rax` will
/// be whatever the peer-side caller passed, which by our convention
/// is just zero (we don't use the return value).
///
/// On the IN side: the GPRs / rsp / rip from `*incoming` are
/// restored. If `*incoming` was populated by `KernelContext::fresh`,
/// this is the task's first run.
///
/// SysV-AMD64: `rdi` = out, `rsi` = incoming, `rax` = return value
/// (always 0 today).
///
/// # Safety
/// - Both contexts must outlive the call.
/// - The incoming context's `rsp` must point at a live kernel stack
///   with at least enough headroom for the task to run a few
///   frames (4 KiB is the bare floor; 16 KiB is typical).
/// - The incoming context's `rip` must point at executable kernel
///   code reachable from CPL=0 with the current CR3.
/// - The caller is responsible for any per-task TSS.rsp0 updates,
///   if the task may be interrupted by a CPL=3→0 trap before its
///   own context-switch happens.
#[unsafe(naked)]
pub unsafe extern "C" fn kernel_switch(
    out: *mut KernelContext,
    incoming: *const KernelContext,
) {
    naked_asm!(
        // ── Save outgoing context ──────────────────────────────
        //
        // SysV: rdi = out, rsi = incoming.
        // Save callee-saved GPRs into out[0..6].
        "mov [rdi + 0],  rbx",
        "mov [rdi + 8],  rbp",
        "mov [rdi + 16], r12",
        "mov [rdi + 24], r13",
        "mov [rdi + 32], r14",
        "mov [rdi + 40], r15",
        // Save the caller's rsp (the post-`call` value — one qword
        // above our current rsp which holds the return-PC).
        "lea rax, [rsp + 8]",
        "mov [rdi + 48], rax",
        // Save the caller's return-PC as `rip`. When something else
        // later switches back to us, the restore-jump below uses
        // this as the target.
        "mov rax, [rsp]",
        "mov [rdi + 56], rax",
        // Save current RFLAGS. Only the IF bit is functionally
        // restored on the load side; other bits are caller-saved
        // per SysV. Critical for the preempt-from-trap path where
        // we switch out of an IF=0 trap-handler context but the
        // executor needs to resume with IF=1.
        "pushfq",
        "pop rax",
        "mov [rdi + 64], rax",

        // ── Restore incoming context ───────────────────────────
        //
        // Load callee-saved GPRs from incoming[0..6].
        "mov rbx, [rsi + 0]",
        "mov rbp, [rsi + 8]",
        "mov r12, [rsi + 16]",
        "mov r13, [rsi + 24]",
        "mov r14, [rsi + 32]",
        "mov r15, [rsi + 40]",
        // Restore rsp BEFORE we touch [rsi + 56] (rcx is caller-
        // saved per SysV, free to use as scratch).
        "mov rsp, [rsi + 48]",
        "mov rcx, [rsi + 56]",
        // Load saved RFLAGS into rdx; we'll use just the IF bit
        // (bit 9) to decide whether to STI/CLI before the final
        // jmp. Other rflags bits are caller-saved per SysV ABI.
        // Use rdx (caller-saved) instead of rax so we can still
        // zero rax for the return-value convention without
        // clobbering the flag-setting test.
        "mov rdx, [rsi + 64]",
        // Zero rax — convention is this fn returns 0; the side
        // resumed-into observes rax=0 in their "post-kernel_switch"
        // continuation. Done BEFORE the IF test so the test's
        // flag side-effect isn't clobbered by the xor.
        "xor eax, eax",
        "test rdx, 0x200",
        "jz 2f",
        // Incoming IF was 1: STI defers interrupt delivery by one
        // instruction (until after the jmp), so the next code
        // executes its first instruction with IF on but no IRQ
        // can land between the STI and the jmp.
        "sti",
        "jmp rcx",
        "2:",
        // Incoming IF was 0: explicitly CLI (so a previously-STI
        // caller doesn't leak IF=1 into a context that wants IF=0,
        // e.g. resuming inside a trap handler).
        "cli",
        "jmp rcx",
    );
}

// Compile-time guarantees that the asm's byte offsets match the
// struct layout. If anyone reorders fields these fire before
// real-HW gets a chance.
const _: () = {
    assert!(core::mem::offset_of!(KernelContext, rbx) == 0);
    assert!(core::mem::offset_of!(KernelContext, rbp) == 8);
    assert!(core::mem::offset_of!(KernelContext, r12) == 16);
    assert!(core::mem::offset_of!(KernelContext, r13) == 24);
    assert!(core::mem::offset_of!(KernelContext, r14) == 32);
    assert!(core::mem::offset_of!(KernelContext, r15) == 40);
    assert!(core::mem::offset_of!(KernelContext, rsp) == 48);
    assert!(core::mem::offset_of!(KernelContext, rip) == 56);
    assert!(core::mem::offset_of!(KernelContext, rflags) == 64);
    // Size 72 + align 16 padding → 80 bytes total.
    assert!(core::mem::size_of::<KernelContext>() == 80);
    assert!(core::mem::align_of::<KernelContext>() == 16);
};

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Sanity: `fresh()` populates the fields the asm expects.
    fn smoke_kernel_ctx_fresh_layout() -> TestResult {
        let ctx = KernelContext::fresh(0xFFFF_FFFF_8000_DEAD, 0xFFFF_FFFF_8000_BEEF, 42);
        if ctx.rsp != 0xFFFF_FFFF_8000_DEAD {
            return TestResult::Fail("rsp wrong");
        }
        if ctx.rip != 0xFFFF_FFFF_8000_BEEF {
            return TestResult::Fail("rip wrong");
        }
        if ctx.r15 != 42 {
            return TestResult::Fail("r15 (arg) wrong");
        }
        if ctx.rbx != 0 || ctx.rbp != 0 || ctx.r12 != 0 || ctx.r13 != 0 || ctx.r14 != 0 {
            return TestResult::Fail("callee-saved should be zeroed on fresh");
        }
        TestResult::Pass
    }

    /// Round-trip: switch from a "main" context to a "child"
    /// context that immediately switches back. Verifies the
    /// asm round-trips state correctly.
    ///
    /// Builds a 4 KiB stack on the test's own (kernel) stack via
    /// a stack array; the child's first thing-to-do is to call
    /// kernel_switch right back to main. The child's "entry" is a
    /// small extern "C" function we define inline.
    fn smoke_kernel_switch_round_trip() -> TestResult {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CHILD_OBSERVED_ARG: AtomicU64 = AtomicU64::new(0);
        static CHILD_CTX: AtomicU64 = AtomicU64::new(0);
        static MAIN_CTX: AtomicU64 = AtomicU64::new(0);

        // Child entry: the trampoline that runs on the child
        // stack. It reads the arg out of `r15` (which we placed
        // there via `KernelContext::fresh`), records it, then
        // switches back to main.
        //
        // NOTE: this is a "trampoline" because on x86_64 the
        // first thing called after `kernel_switch`'s `jmp rcx` is
        // whatever sits at `incoming.rip`. We can't pass args via
        // a normal Rust fn call — the calling convention happens
        // BEFORE our entry. We use r15 as a smuggled register.
        #[unsafe(naked)]
        unsafe extern "C" fn child_trampoline() -> ! {
            naked_asm!(
                // r15 holds the arg per KernelContext::fresh. Move
                // to rdi so we can call regular Rust.
                "mov rdi, r15",
                "call {body}",
                // body shouldn't return; if it does, halt.
                "ud2",
                body = sym child_body,
            );
        }

        extern "C" fn child_body(arg: u64) -> ! {
            CHILD_OBSERVED_ARG.store(arg, Ordering::Release);
            // Switch back to main. We load both contexts by pointer
            // from globals because the child runs on a different
            // stack and we can't reach `main_ctx` via the test's
            // own stack frame.
            let child_ctx = CHILD_CTX.load(Ordering::Acquire) as *mut KernelContext;
            let main_ctx = MAIN_CTX.load(Ordering::Acquire) as *const KernelContext;
            unsafe { kernel_switch(child_ctx, main_ctx) };
            // If main switches back to us, we'd resume here — but
            // this test only does one round trip, so spin.
            loop {
                core::hint::spin_loop();
            }
        }

        // 4 KiB scratch stack. Box it so the child's RSP points at
        // an alloc-owned region, not a Vec that might move.
        let mut stack = alloc::boxed::Box::<[u8; 4096]>::new([0u8; 4096]);
        // Stack grows down — set top to the highest aligned byte.
        let stack_top = (stack.as_mut_ptr() as u64).wrapping_add(4096) & !0xFu64;

        let mut main_ctx = KernelContext::default();
        let mut child_ctx = KernelContext::fresh(
            stack_top,
            child_trampoline as u64,
            /* arg = */ 0xDEAD_BEEF,
        );

        // Publish the contexts so child_body can find them.
        CHILD_CTX.store(&mut child_ctx as *mut _ as u64, Ordering::Release);
        MAIN_CTX.store(&mut main_ctx as *mut _ as u64, Ordering::Release);

        // Switch into child; the child runs, records arg, switches
        // back. We resume here.
        // SAFETY: child_ctx is a fresh ctx with a live stack +
        // valid entry point.
        unsafe { kernel_switch(&mut main_ctx, &child_ctx) };

        let observed = CHILD_OBSERVED_ARG.load(Ordering::Acquire);
        if observed != 0xDEAD_BEEF {
            return TestResult::Fail("child didn't observe arg");
        }
        TestResult::Pass
    }

    kernel_test_in!("arch/kernel_ctx", smoke_kernel_ctx_fresh_layout);
    kernel_test_in!("arch/kernel_ctx", smoke_kernel_switch_round_trip);
}
