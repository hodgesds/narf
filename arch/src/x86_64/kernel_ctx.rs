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
//! `KernelContext` is 96 bytes, 16-byte aligned, holding the
//! callee-saved GPRs (SysV-AMD64), RSP, saved RIP/RFLAGS, and the opaque
//! hardware-domain state. Byte offsets
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
//!    64     rflags
//!    72     domain_state (PKRS or CR3)
//!    80     domain_kind (0 inactive, 1 PKRS, 2 CR3/PCID)
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
// SAFETY: Valid memory or trusted environment
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
    /// Architecture-owned protection state. The executor deliberately cannot
    /// interpret this pair; `kernel_switch` saves it before touching the
    /// outgoing context and restores it only after its final memory access.
    pub domain_state: u64,
    pub domain_kind: u64,
}

impl KernelContext {
    /// All-zero context, usable in `const` initializers (e.g. a
    /// per-CPU static array). A zero context is never switched
    /// *into* before a `kernel_switch` save half has populated it;
    /// it only exists so persistent per-CPU storage can be declared
    /// `const` without a runtime initializer.
    pub const fn zeroed() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
            rflags: 0,
            domain_state: 0,
            domain_kind: 0,
        }
    }

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
            // A fresh task inherits the neutral state in which the executor
            // dispatches it. Its first switch-out captures a concrete state.
            domain_state: 0,
            domain_kind: 0,
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
pub unsafe extern "C" fn kernel_switch(out: *mut KernelContext, incoming: *const KernelContext) {
    naked_asm!(
        // A switch is one indivisible ownership transfer. Capture the caller's
        // IF state, then prevent a trap from observing half-saved domain/GPR
        // state. The incoming context's IF is restored at the tail.
        "pushfq",
        "pop r11",
        "cli",
        // Capture task-local domain rights and enter neutral FRAME state before
        // writing `out`. This ordering lets a confined task yield safely even
        // when its current rights deny scheduler/arch storage. CR4.PKS/PCIDE
        // are boot-stable; use the maintained cache because a live CR4 read
        // exits under KVM/SVM.
        "mov rax, qword ptr [rip + NARF_X86_CACHED_CR4]",
        "bt rax, 24",
        "jc 3f",
        "bt rax, 17",
        "jnc 5f",
        "mov r8, [rip + NARF_X86_FRAME_PML4]",
        "test r8, r8",
        "jz 5f",
        "mov r9, cr3",
        "or r8, 1",
        // Syscall/trap entry normally put the continuation in this exact
        // FRAME root+PCID before it can yield. Canonicalise that already-neutral
        // state as kind 0 instead of issuing a serialising same-value CR3 write.
        "cmp r9, r8",
        "je 5f",
        "bts r8, 63",
        "mov cr3, r8",
        "mov [rdi + 72], r9",
        "mov qword ptr [rdi + 80], 2",
        "jmp 6f",
        "3:",
        "mov ecx, 0x6e1",
        "rdmsr",
        "shl rdx, 32",
        "or rax, rdx",
        "mov r8, rax",
        // PKRS=0 is the neutral FRAME state. As with an identical FRAME CR3,
        // kind 0 accurately records that no restore is needed on resume.
        "test r8, r8",
        "jz 5f",
        "xor eax, eax",
        "xor edx, edx",
        "wrmsr",
        "mov [rdi + 72], r8",
        "mov qword ptr [rdi + 80], 1",
        "jmp 6f",
        "5:",
        "mov qword ptr [rdi + 72], 0",
        "mov qword ptr [rdi + 80], 0",
        "6:",
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
        "mov [rdi + 64], r11",
        // ── Restore incoming context ───────────────────────────
        //
        // Load callee-saved GPRs from incoming[0..6].
        "mov rbx, [rsi + 0]",
        "mov rbp, [rsi + 8]",
        "mov r12, [rsi + 16]",
        "mov r13, [rsi + 24]",
        "mov r14, [rsi + 32]",
        "mov r15, [rsi + 40]",
        // Restore rsp before loading the resume PC. r11 is caller-saved and
        // remains available while the PKRS path uses ECX for its MSR index.
        "mov rsp, [rsi + 48]",
        "mov r11, [rsi + 56]",
        // Load saved RFLAGS into rdx; we'll use just the IF bit
        // (bit 9) to decide whether to STI/CLI before the final
        // jmp. Other rflags bits are caller-saved per SysV ABI.
        // Use rdx (caller-saved) instead of rax so we can still
        // zero rax for the return-value convention without
        // clobbering the flag-setting test.
        "mov rdx, [rsi + 64]",
        // Read all incoming domain fields while FRAME is still neutral. Their
        // restore is deliberately the final privileged operation before the
        // interrupt-state handoff and branch; no memory is touched afterward.
        "mov r8, [rsi + 72]",
        "mov r9, [rsi + 80]",
        // Zero rax — convention is this fn returns 0; the side
        // resumed-into observes rax=0 in their "post-kernel_switch"
        // continuation. Done BEFORE the IF test so the test's
        // flag side-effect isn't clobbered by the xor.
        "xor eax, eax",
        "cmp r9, 1",
        "je 7f",
        "cmp r9, 2",
        "je 8f",
        "jmp 9f",
        "7:",
        "mov rax, r8",
        "mov r10, rdx",
        "shr rdx, 32",
        "mov ecx, 0x6e1",
        "wrmsr",
        "mov rdx, r10",
        "jmp 9f",
        "8:",
        "bts r8, 63",
        "mov cr3, r8",
        "9:",
        "xor eax, eax",
        "test rdx, 0x200",
        "jz 2f",
        // Incoming IF was 1: STI defers interrupt delivery by one
        // instruction (until after the jmp), so the next code
        // executes its first instruction with IF on but no IRQ
        // can land between the STI and the jmp.
        "sti",
        "jmp r11",
        "2:",
        // Incoming IF was 0: explicitly CLI (so a previously-STI
        // caller doesn't leak IF=1 into a context that wants IF=0,
        // e.g. resuming inside a trap handler).
        "cli",
        "jmp r11",
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
    assert!(core::mem::offset_of!(KernelContext, domain_state) == 72);
    assert!(core::mem::offset_of!(KernelContext, domain_kind) == 80);
    // Size 88 + align 16 padding → 96 bytes total.
    assert!(core::mem::size_of::<KernelContext>() == 96);
    assert!(core::mem::align_of::<KernelContext>() == 16);
};

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
extern crate alloc;

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
            // SAFETY: both pointers were published by the test driver from
            // live `KernelContext` locals that outlive this switch; `child_ctx`
            // is the running context (safe to save into) and `main_ctx` is the
            // suspended caller to resume.
            // SAFETY: Valid memory or trusted environment
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
            child_trampoline as usize as u64,
            /* arg = */ 0xDEAD_BEEF,
        );

        // Publish the contexts so child_body can find them.
        CHILD_CTX.store(&mut child_ctx as *mut _ as u64, Ordering::Release);
        MAIN_CTX.store(&mut main_ctx as *mut _ as u64, Ordering::Release);

        // Switch into child; the child runs, records arg, switches
        // back. We resume here.
        // SAFETY: child_ctx is a fresh ctx with a live stack +
        // valid entry point.
        // SAFETY: Valid memory or trusted environment
        unsafe { kernel_switch(&mut main_ctx, &child_ctx) };

        let observed = CHILD_OBSERVED_ARG.load(Ordering::Acquire);
        if observed != 0xDEAD_BEEF {
            return TestResult::Fail("child didn't observe arg");
        }
        TestResult::Pass
    }

    /// Callee-saved registers (rbx, rbp, r12-r15) must round-trip
    /// across a kernel_switch ping-pong. The peer side observes
    /// values we wrote before switching out, and we observe the
    /// caller-side values on resume — meaning rbx etc. were
    /// correctly saved and restored through the OUT and IN halves.
    fn smoke_kernel_switch_preserves_callee_saved() -> TestResult {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CHILD_OBSERVED_RBX: AtomicU64 = AtomicU64::new(0);
        static CHILD_OBSERVED_R12: AtomicU64 = AtomicU64::new(0);
        static CHILD_CTX: AtomicU64 = AtomicU64::new(0);
        static MAIN_CTX: AtomicU64 = AtomicU64::new(0);

        #[unsafe(naked)]
        unsafe extern "C" fn child_trampoline() -> ! {
            naked_asm!(
                "mov rdi, rbx",     // pass observed rbx as arg 0
                "mov rsi, r12",     // and r12 as arg 1
                "call {body}",
                "ud2",
                body = sym child_body,
            );
        }

        extern "C" fn child_body(rbx_seen: u64, r12_seen: u64) -> ! {
            CHILD_OBSERVED_RBX.store(rbx_seen, Ordering::Release);
            CHILD_OBSERVED_R12.store(r12_seen, Ordering::Release);
            let child_ctx = CHILD_CTX.load(Ordering::Acquire) as *mut KernelContext;
            let main_ctx = MAIN_CTX.load(Ordering::Acquire) as *const KernelContext;
            // SAFETY: both pointers were published by the test driver from live
            // `KernelContext` locals that outlive this switch; `child_ctx` is
            // the running context and `main_ctx` is the caller to resume.
            // SAFETY: Valid memory or trusted environment
            unsafe { kernel_switch(child_ctx, main_ctx) };
            loop {
                core::hint::spin_loop();
            }
        }

        let mut stack = alloc::boxed::Box::<[u8; 4096]>::new([0u8; 4096]);
        let stack_top = (stack.as_mut_ptr() as u64).wrapping_add(4096) & !0xFu64;
        let mut main_ctx = KernelContext::default();
        let mut child_ctx = KernelContext {
            rsp: stack_top,
            rip: child_trampoline as usize as u64,
            rbx: 0xAAAA_AAAA_AAAA_AAAA,
            r12: 0xBBBB_BBBB_BBBB_BBBB,
            rflags: 0x202,
            ..KernelContext::default()
        };
        CHILD_CTX.store(&mut child_ctx as *mut _ as u64, Ordering::Release);
        MAIN_CTX.store(&mut main_ctx as *mut _ as u64, Ordering::Release);

        // SAFETY: `main_ctx` is the live running context to save into and
        // `child_ctx` is a fresh context with a boxed stack still in scope and
        // a valid entry point, so kernel_switch can switch into it.
        // SAFETY: Valid memory or trusted environment
        unsafe { kernel_switch(&mut main_ctx, &child_ctx) };

        if CHILD_OBSERVED_RBX.load(Ordering::Acquire) != 0xAAAA_AAAA_AAAA_AAAA {
            return TestResult::Fail("child saw wrong rbx — kernel_switch didn't restore");
        }
        if CHILD_OBSERVED_R12.load(Ordering::Acquire) != 0xBBBB_BBBB_BBBB_BBBB {
            return TestResult::Fail("child saw wrong r12 — kernel_switch didn't restore");
        }
        TestResult::Pass
    }

    /// IF=1 on entry → kernel_switch save records IF=1 → load
    /// restores via STI → switched-into code runs with IRQs on.
    /// IF=0 on entry → save records IF=0 → load restores via CLI
    /// → switched-into code runs with IRQs off. Both directions
    /// must round-trip the saved-IF state through the inbound
    /// context's rflags field.
    fn smoke_kernel_switch_preserves_if_flag() -> TestResult {
        use core::arch::asm;
        use core::sync::atomic::{AtomicU64, Ordering};
        static CHILD_IF_OBSERVED: AtomicU64 = AtomicU64::new(0xFFFF);
        static CHILD_CTX: AtomicU64 = AtomicU64::new(0);
        static MAIN_CTX: AtomicU64 = AtomicU64::new(0);

        #[unsafe(naked)]
        unsafe extern "C" fn child_trampoline() -> ! {
            naked_asm!(
                // Sample RFLAGS at entry into rdi (arg 0).
                "pushfq",
                "pop rdi",
                "call {body}",
                "ud2",
                body = sym child_body,
            );
        }

        extern "C" fn child_body(rflags_at_entry: u64) -> ! {
            // Mask down to the IF bit (0x200). The other bits are
            // ABI-volatile so they're unsafe to assert against.
            CHILD_IF_OBSERVED.store(rflags_at_entry & 0x200, Ordering::Release);
            let child_ctx = CHILD_CTX.load(Ordering::Acquire) as *mut KernelContext;
            let main_ctx = MAIN_CTX.load(Ordering::Acquire) as *const KernelContext;
            // SAFETY: both pointers were published by the test driver from live
            // `KernelContext` locals that outlive this switch; `child_ctx` is
            // the running context and `main_ctx` is the caller to resume.
            // SAFETY: Valid memory or trusted environment
            unsafe { kernel_switch(child_ctx, main_ctx) };
            loop {
                core::hint::spin_loop();
            }
        }

        let mut stack = alloc::boxed::Box::<[u8; 4096]>::new([0u8; 4096]);
        let stack_top = (stack.as_mut_ptr() as u64).wrapping_add(4096) & !0xFu64;

        // Case 1: switch in with IF=1 stored in child_ctx. Child
        // should observe IF=1.
        let mut main_ctx = KernelContext::default();
        let mut child_ctx = KernelContext::fresh(stack_top, child_trampoline as usize as u64, 0);
        // KernelContext::fresh seeds rflags = 0x202 (IF=1). Verify.
        if child_ctx.rflags & 0x200 == 0 {
            return TestResult::Fail("fresh() didn't set IF=1 in rflags");
        }
        CHILD_CTX.store(&mut child_ctx as *mut _ as u64, Ordering::Release);
        MAIN_CTX.store(&mut main_ctx as *mut _ as u64, Ordering::Release);
        // Disable IF locally before the switch so the load half
        // is the ONLY way IF could come back on for the child.
        // If kernel_switch didn't restore IF from rflags, the
        // child would observe IF=0 (matching our pre-switch state).
        // SAFETY: `cli` only clears IF; this test runs at CPL=0 in the kernel
        // and re-enables interrupts via the `sti` below before returning.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!("cli", options(nomem, nostack));
        }
        // SAFETY: `main_ctx` is the live running context and `child_ctx` is a
        // fresh context with a live boxed stack and valid entry point.
        // SAFETY: Valid memory or trusted environment
        unsafe { kernel_switch(&mut main_ctx, &child_ctx) };
        // The child set IF=1 on entry (via STI in load half) and
        // switched back. On return, our IF state was restored from
        // main_ctx.rflags — which kernel_switch saved on the way
        // out. Since we CLI'd before the switch, main_ctx.rflags
        // recorded IF=0, so we resume with IF=0.
        // SAFETY: `sti` only sets IF; a valid IDT is installed in this kernel
        // test context, so re-enabling interrupts here is sound.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!("sti", options(nomem, nostack));
        } // restore for the rest of the suite

        let observed = CHILD_IF_OBSERVED.load(Ordering::Acquire);
        if observed != 0x200 {
            return TestResult::Fail("child observed IF=0 when context said IF=1");
        }

        // Case 2: switch in with IF=0. Child observes IF=0.
        CHILD_IF_OBSERVED.store(0xFFFF, Ordering::Release);
        let mut main_ctx = KernelContext::default();
        let mut child_ctx = KernelContext::fresh(stack_top, child_trampoline as usize as u64, 0);
        child_ctx.rflags = 0x2; // reserved bit 1 only; IF=0
        CHILD_CTX.store(&mut child_ctx as *mut _ as u64, Ordering::Release);
        MAIN_CTX.store(&mut main_ctx as *mut _ as u64, Ordering::Release);
        // SAFETY: `main_ctx` is the live running context and `child_ctx` is a
        // fresh context with a live boxed stack and valid entry point.
        // SAFETY: Valid memory or trusted environment
        unsafe { kernel_switch(&mut main_ctx, &child_ctx) };
        // Child observed pre-restore RFLAGS via pushfq — that
        // reflects what kernel_switch arranged for the child. STI
        // is deferred by one instruction, so the FIRST instruction
        // (pushfq) runs before IF actually toggles. We CLI'd before
        // the switch so the inherited IF was 0; the load half's
        // CLI path keeps it 0; child sees IF=0.
        let observed = CHILD_IF_OBSERVED.load(Ordering::Acquire);
        if observed != 0 {
            return TestResult::Fail("child observed IF=1 when context said IF=0");
        }
        TestResult::Pass
    }

    /// Ping-pong test: switch back and forth between two contexts
    /// N times, verifying we end up back at the original site with
    /// the correct count. Catches save/restore asymmetries that a
    /// single round-trip would miss (e.g., a stack offset that's
    /// wrong by 8 bytes accumulates over many switches).
    fn smoke_kernel_switch_ping_pong() -> TestResult {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        static CHILD_CTX: AtomicU64 = AtomicU64::new(0);
        static MAIN_CTX: AtomicU64 = AtomicU64::new(0);
        const ROUND_TRIPS: u64 = 32;

        #[unsafe(naked)]
        unsafe extern "C" fn child_trampoline() -> ! {
            naked_asm!(
                "call {body}",
                "ud2",
                body = sym child_body,
            );
        }

        extern "C" fn child_body() -> ! {
            let child_ctx = CHILD_CTX.load(Ordering::Acquire) as *mut KernelContext;
            let main_ctx = MAIN_CTX.load(Ordering::Acquire) as *const KernelContext;
            loop {
                COUNTER.fetch_add(1, Ordering::AcqRel);
                // SAFETY: pointers live as long as the test fn does;
                // both contexts owned by stack-locals in caller.
                // SAFETY: Valid memory or trusted environment
                unsafe { kernel_switch(child_ctx, main_ctx) };
                // Resumed here when main switches us back. Loop.
            }
        }

        COUNTER.store(0, Ordering::Release);
        let mut stack = alloc::boxed::Box::<[u8; 8192]>::new([0u8; 8192]);
        let stack_top = (stack.as_mut_ptr() as u64).wrapping_add(8192) & !0xFu64;
        let mut main_ctx = KernelContext::default();
        let mut child_ctx = KernelContext::fresh(stack_top, child_trampoline as usize as u64, 0);
        CHILD_CTX.store(&mut child_ctx as *mut _ as u64, Ordering::Release);
        MAIN_CTX.store(&mut main_ctx as *mut _ as u64, Ordering::Release);

        for _ in 0..ROUND_TRIPS {
            // SAFETY: same.
            unsafe { kernel_switch(&mut main_ctx, &child_ctx) };
        }

        let observed = COUNTER.load(Ordering::Acquire);
        if observed != ROUND_TRIPS {
            return TestResult::Fail("ping-pong counter mismatch");
        }
        TestResult::Pass
    }

    kernel_test_in!("arch/kernel_ctx", smoke_kernel_ctx_fresh_layout);
    kernel_test_in!("arch/kernel_ctx", smoke_kernel_switch_round_trip);
    kernel_test_in!(
        "arch/kernel_ctx",
        smoke_kernel_switch_preserves_callee_saved
    );
    kernel_test_in!("arch/kernel_ctx", smoke_kernel_switch_preserves_if_flag);
    kernel_test_in!("arch/kernel_ctx", smoke_kernel_switch_ping_pong);
}
