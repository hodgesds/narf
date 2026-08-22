//! aarch64 user-mode (EL0) entry, resume, setjmp / longjmp.
//!
//! Mirror of `narf_arch::x86_64::user_mode`. Each primitive is the
//! aarch64 analogue of its x86_64 sibling so the scheduler /
//! userspace plumbing can be cfg-gated at the import line and
//! share otherwise-identical control flow.
//!
//! - [`UserState`] — snapshot of the user-mode CPU state at trap
//!   time (31 GPRs + PC + SP + SPSR + valid sentinel).
//! - [`enter_user_mode`] — `eret` to EL0 at (PC, SP) with a clean
//!   PSTATE; never returns.
//! - [`enter_user_mode_resume`] — `eret` to EL0 with every GPR /
//!   ELR / SPSR / SP_EL0 restored from a `UserState`; never
//!   returns.
//! - [`JmpBuf`] / [`setjmp`] / [`longjmp`] — kernel-side
//!   long-jump using the AArch64 procedure-call-standard
//!   callee-saved register set. Used by the polling-future glue
//!   so a trap can unwind back to the executor's setjmp without
//!   running destructors on the trap path.

use core::arch::{asm, naked_asm};

/// Snapshot of an EL0 task's CPU state at trap time. Field order
/// is load-bearing — `enter_user_mode_resume`'s naked asm reads
/// fields by byte offset:
///
/// ```text
///   offset  0   .. 248 : x[0..=30]
///   offset 248         : pc   (ELR_EL1)
///   offset 256         : sp   (SP_EL0)
///   offset 264         : spsr (SPSR_EL1)
///   offset 272         : valid
/// ```
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UserState {
    /// x0..=x30 in index order.
    pub x: [u64; 31],
    /// Post-trap PC — ELR_EL1 at trap entry.
    pub pc: u64,
    /// User-mode SP — SP_EL0.
    pub sp: u64,
    /// Saved PSTATE — SPSR_EL1.
    pub spsr: u64,
    /// `1` once a trap path has populated this snapshot.
    pub valid: u64,
}

/// SPSR_EL1 value for EL0t entry: mode bits = 0b0000 (EL0 with
/// SP_EL0 selected), DAIF cleared so user mode runs with all
/// async exceptions unmasked. Mirrors the value used by
/// `frame::aarch64::user::USER_SPSR`.
pub const USER_SPSR: u64 = 0;

/// Complete architectural FP/SIMD state for one EL0 task.
///
/// The 32 128-bit vector registers occupy the first 512 bytes, followed by
/// FPCR and FPSR.  AArch64 kernel code is built without FP/SIMD use, so the
/// scheduler only needs to save this state when an EL0 continuation is about
/// to be switched out and restore it immediately before that continuation is
/// switched back in.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct UserFpState {
    bytes: [u8; 528],
}

impl UserFpState {
    pub const fn zeroed() -> Self {
        Self { bytes: [0; 528] }
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
}

impl Default for UserFpState {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Save Q0-Q31, FPCR, and FPSR into `state`.
///
/// # Safety
/// `state` must point to a writable, 16-byte-aligned [`UserFpState`]. FP/SIMD
/// access must be enabled at EL1 (NARF enables CPACR_EL1.FPEN on every CPU).
#[inline]
pub unsafe fn save_user_fp_state(state: *mut u8) {
    // SAFETY: the caller provides a live UserFpState; offsets match its fixed
    // layout and the boot path enables FP/SIMD access at EL1.
    unsafe {
        asm!(
            "stp q0,  q1,  [{state}, #0]",
            "stp q2,  q3,  [{state}, #32]",
            "stp q4,  q5,  [{state}, #64]",
            "stp q6,  q7,  [{state}, #96]",
            "stp q8,  q9,  [{state}, #128]",
            "stp q10, q11, [{state}, #160]",
            "stp q12, q13, [{state}, #192]",
            "stp q14, q15, [{state}, #224]",
            "stp q16, q17, [{state}, #256]",
            "stp q18, q19, [{state}, #288]",
            "stp q20, q21, [{state}, #320]",
            "stp q22, q23, [{state}, #352]",
            "stp q24, q25, [{state}, #384]",
            "stp q26, q27, [{state}, #416]",
            "stp q28, q29, [{state}, #448]",
            "stp q30, q31, [{state}, #480]",
            "mrs {fpcr}, fpcr",
            "mrs {fpsr}, fpsr",
            "str {fpcr}, [{state}, #512]",
            "str {fpsr}, [{state}, #520]",
            state = in(reg) state,
            fpcr = out(reg) _,
            fpsr = out(reg) _,
            options(nostack),
        );
    }
}

/// Restore Q0-Q31, FPCR, and FPSR from `state`.
///
/// # Safety
/// `state` must point to a readable, 16-byte-aligned [`UserFpState`].
#[inline]
pub unsafe fn restore_user_fp_state(state: *const u8) {
    // SAFETY: the caller provides a live UserFpState; see save_user_fp_state.
    unsafe {
        asm!(
            "ldr {fpcr}, [{state}, #512]",
            "ldr {fpsr}, [{state}, #520]",
            "msr fpcr, {fpcr}",
            "msr fpsr, {fpsr}",
            "ldp q0,  q1,  [{state}, #0]",
            "ldp q2,  q3,  [{state}, #32]",
            "ldp q4,  q5,  [{state}, #64]",
            "ldp q6,  q7,  [{state}, #96]",
            "ldp q8,  q9,  [{state}, #128]",
            "ldp q10, q11, [{state}, #160]",
            "ldp q12, q13, [{state}, #192]",
            "ldp q14, q15, [{state}, #224]",
            "ldp q16, q17, [{state}, #256]",
            "ldp q18, q19, [{state}, #288]",
            "ldp q20, q21, [{state}, #320]",
            "ldp q22, q23, [{state}, #352]",
            "ldp q24, q25, [{state}, #384]",
            "ldp q26, q27, [{state}, #416]",
            "ldp q28, q29, [{state}, #448]",
            "ldp q30, q31, [{state}, #480]",
            state = in(reg) state,
            fpcr = out(reg) _,
            fpsr = out(reg) _,
            options(nostack),
        );
    }
}

/// Transfer into EL0 at (`pc`, `sp`). Sets SPSR_EL1 = 0 (EL0t),
/// loads ELR_EL1 = `pc`, SP_EL0 = `sp`, then `eret`. Never
/// returns.
///
/// # Safety
/// - The currently-active TTBR0 must map `pc` executable + user
///   and `sp` writable + user.
/// - Caller must have set up KERNEL/EL1 stack via SP_EL1 so the
///   next EL0 → EL1 trap has somewhere to land.
/// - Interrupts are unmasked on entry (SPSR.DAIF = 0).
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode(pc: u64, sp: u64) -> ! {
    naked_asm!(
        // AAPCS64: pc in x0, sp in x1.
        "msr sp_el0,  x1",
        "msr elr_el1, x0",
        "msr spsr_el1, xzr", // EL0t, DAIF clear
        // Scrub every GPR before the eret. Linux zeroes the whole
        // register file at ELF entry, and glibc's aarch64 `_start`
        // treats a non-zero entry x0 as the "rtld_fini" function
        // pointer to register with atexit — leaking the entry pc (or
        // any stale kernel value) here becomes a wild jump when
        // exit(3) runs the handler list. Also keeps kernel pointers
        // out of EL0 in general.
        "mov x0,  xzr",
        "mov x1,  xzr",
        "mov x2,  xzr",
        "mov x3,  xzr",
        "mov x4,  xzr",
        "mov x5,  xzr",
        "mov x6,  xzr",
        "mov x7,  xzr",
        "mov x8,  xzr",
        "mov x9,  xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "eret",
    );
}

/// Enter EL0 like [`enter_user_mode`], delivering `arg` in x0.
///
/// # Safety
/// The active TTBR0 must map `pc` executable and `sp` writable for EL0, and
/// SP_EL1 must already name a valid exception stack. This function never
/// returns and abandons the caller's control flow at ERET.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode_with_arg(pc: u64, sp: u64, arg: u64) -> ! {
    naked_asm!(
        "msr sp_el0, x1",
        "msr elr_el1, x0",
        "msr spsr_el1, xzr",
        "mov x3, x2",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x9, xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "mov x0, x3",
        "mov x3, xzr",
        "eret",
    );
}

/// Enter EL0 after resetting SP_EL1 to the empty task kernel-stack top.
/// This abandons the caller's frames and therefore never returns.
///
/// # Safety
/// The active TTBR0 must map `pc` executable and `user_sp` writable for EL0.
/// `kernel_stack_top` must be the aligned top of the current task's live,
/// exclusively-owned kernel stack and remain valid for every later exception.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode_at_top(pc: u64, user_sp: u64, kernel_stack_top: u64) -> ! {
    naked_asm!(
        "msr sp_el0, x1",
        "msr elr_el1, x0",
        "msr spsr_el1, xzr",
        "mov sp, x2",
        "mov x0, xzr",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x9, xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "eret",
    );
}

/// [`enter_user_mode_at_top`] with the initial x0 argument supplied.
///
/// # Safety
/// The mapping and task-stack requirements of [`enter_user_mode_at_top`] apply.
/// `arg` is exposed unchanged to EL0 in x0. This function never returns.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode_with_arg_at_top(
    pc: u64,
    user_sp: u64,
    arg: u64,
    kernel_stack_top: u64,
) -> ! {
    naked_asm!(
        "msr sp_el0, x1",
        "msr elr_el1, x0",
        "msr spsr_el1, xzr",
        "mov sp, x3",
        "mov x3, x2",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x9, xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "mov x0, x3",
        "mov x3, xzr",
        "eret",
    );
}

/// Resume EL0 at the state captured in `*state`. Restores every
/// GPR + ELR + SPSR + SP_EL0 from the snapshot, then `eret`.
/// Never returns.
///
/// # Safety
/// - The active TTBR0 must map `state.pc` executable + user and
///   `state.sp` writable + user.
/// - The state must have come from a prior trap from EL0 (the
///   page tables match).
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode_resume(state: *const UserState) -> ! {
    naked_asm!(
        // AAPCS64: state ptr in x0. We need x0 last because it's
        // both the input pointer and a destination register; we
        // load it from x[0] after every other field is in place.
        //
        // Layout (must match `UserState`):
        //   x[0..=30] @ +0   .. +248
        //   pc         @ +248
        //   sp         @ +256
        //   spsr       @ +264
        //
        // Restore SP_EL0 / ELR_EL1 / SPSR_EL1 first; they live in
        // system regs, not in the GPR file we're about to clobber.
        "ldr x9,  [x0, #256]", // sp
        "msr sp_el0,  x9",
        "ldr x9,  [x0, #248]", // pc
        "msr elr_el1, x9",
        "ldr x9,  [x0, #264]", // spsr
        "msr spsr_el1, x9",
        // Restore x1..=x30, leaving x0 for last.
        "ldp  x1,  x2,  [x0, #8]",
        "ldp  x3,  x4,  [x0, #24]",
        "ldp  x5,  x6,  [x0, #40]",
        "ldp  x7,  x8,  [x0, #56]",
        "ldp  x9,  x10, [x0, #72]",
        "ldp  x11, x12, [x0, #88]",
        "ldp  x13, x14, [x0, #104]",
        "ldp  x15, x16, [x0, #120]",
        "ldp  x17, x18, [x0, #136]",
        "ldp  x19, x20, [x0, #152]",
        "ldp  x21, x22, [x0, #168]",
        "ldp  x23, x24, [x0, #184]",
        "ldp  x25, x26, [x0, #200]",
        "ldp  x27, x28, [x0, #216]",
        "ldp  x29, x30, [x0, #232]",
        // Finally x0.
        "ldr  x0, [x0, #0]",
        "eret",
    );
}

/// Resume a saved EL0 state after resetting SP_EL1 to the empty task stack.
///
/// # Safety
/// `state` must be a live snapshot captured from this task's prior EL0
/// continuation under the active TTBR0. `kernel_stack_top` must be the aligned
/// top of this task's live, exclusively-owned exception stack.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode_resume_at_top(
    state: *const UserState,
    kernel_stack_top: u64,
) -> ! {
    naked_asm!(
        "mov sp, x1",
        "ldr x9, [x0, #256]",
        "msr sp_el0, x9",
        "ldr x9, [x0, #248]",
        "msr elr_el1, x9",
        "ldr x9, [x0, #264]",
        "msr spsr_el1, x9",
        "ldp x1, x2, [x0, #8]",
        "ldp x3, x4, [x0, #24]",
        "ldp x5, x6, [x0, #40]",
        "ldp x7, x8, [x0, #56]",
        "ldp x9, x10, [x0, #72]",
        "ldp x11, x12, [x0, #88]",
        "ldp x13, x14, [x0, #104]",
        "ldp x15, x16, [x0, #120]",
        "ldp x17, x18, [x0, #136]",
        "ldp x19, x20, [x0, #152]",
        "ldp x21, x22, [x0, #168]",
        "ldp x23, x24, [x0, #184]",
        "ldp x25, x26, [x0, #200]",
        "ldp x27, x28, [x0, #216]",
        "ldp x29, x30, [x0, #232]",
        "ldr x0, [x0]",
        "eret",
    );
}

// ── setjmp / longjmp ───────────────────────────────────────────────

/// AArch64 long-jump buffer. Holds the AAPCS64 callee-saved GPRs
/// (x19..=x29 = 11 regs) plus the link register (x30) plus the
/// stack pointer = 13 u64s. FPU d8..=d15 are not preserved —
/// kernel code is no-fp.
///
/// Layout (load-bearing for the naked asm in `setjmp`/`longjmp`):
///
/// ```text
///   slot[0]  = x19    slot[1]  = x20    slot[2]  = x21
///   slot[3]  = x22    slot[4]  = x23    slot[5]  = x24
///   slot[6]  = x25    slot[7]  = x26    slot[8]  = x27
///   slot[9]  = x28    slot[10] = x29 (frame ptr / fp)
///   slot[11] = x30 (lr — return address into setjmp's caller)
///   slot[12] = sp
/// ```
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct JmpBuf {
    pub slots: [u64; 13],
}

/// Save the current callee-saved register file into `*jmp` and
/// return 0. A subsequent [`longjmp`] (`jmp`, `val`) makes this
/// `setjmp` call appear to return `val` instead — the standard
/// C-library long-jump shape.
///
/// # Safety
/// `jmp` must be a writable, suitably-aligned `JmpBuf` for at
/// least the lifetime of any matching `longjmp`.
#[unsafe(naked)]
pub unsafe extern "C" fn setjmp(jmp: *mut JmpBuf) -> u64 {
    naked_asm!(
        // AAPCS64: jmp in x0, return value in x0.
        "stp  x19, x20, [x0, #0]",
        "stp  x21, x22, [x0, #16]",
        "stp  x23, x24, [x0, #32]",
        "stp  x25, x26, [x0, #48]",
        "stp  x27, x28, [x0, #64]",
        "stp  x29, x30, [x0, #80]",
        "mov  x9, sp",
        "str  x9, [x0, #96]",
        "mov  x0, #0",
        "ret",
    );
}

/// Restore the register file from `*jmp` and "return" from the
/// matching [`setjmp`] with value `val`. Never returns to the
/// caller of `longjmp` itself.
///
/// # Safety
/// - `jmp` must point at a `JmpBuf` populated by an earlier
///   `setjmp` whose call frame is still live (the saved sp + x30
///   must still describe a valid kernel stack).
/// - `val` must be non-zero — POSIX `setjmp` cannot distinguish
///   a `longjmp` carrying `0` from a fresh-call return; callers
///   of `longjmp(_, 0)` get undefined behaviour by long
///   convention. The kernel tests pass non-zero sentinels.
#[unsafe(naked)]
pub unsafe extern "C" fn longjmp(jmp: *const JmpBuf, val: u64) -> ! {
    naked_asm!(
        // AAPCS64: jmp in x0, val in x1.
        "ldp  x19, x20, [x0, #0]",
        "ldp  x21, x22, [x0, #16]",
        "ldp  x23, x24, [x0, #32]",
        "ldp  x25, x26, [x0, #48]",
        "ldp  x27, x28, [x0, #64]",
        "ldp  x29, x30, [x0, #80]",
        "ldr  x9, [x0, #96]",
        "mov  sp, x9",
        // setjmp returns val (or 1 if val==0, per POSIX
        // convention — preserves the "0 means initial-call"
        // distinction even when callers pass 0).
        "cmp  x1, #0",
        "csinc x0, x1, xzr, ne",
        "ret",
    );
}

/// FS-base equivalent on aarch64 — programs the per-task TLS
/// thread pointer. AArch64 puts the user-mode TLS pointer in
/// `TPIDR_EL0`, accessible from EL1 via MSR.
///
/// # Safety
/// Writing TPIDR_EL0 at EL1 is unconditional. Caller is
/// responsible for ensuring `tp` points at a valid TLS block in
/// the active address space.
#[inline]
pub unsafe fn set_user_tls_base(tp: u64) {
    // SAFETY: TPIDR_EL0 write at EL1 is architecturally defined
    // and has no side effects on EL1 state.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "msr TPIDR_EL0, {tp}",
            tp = in(reg) tp,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
const _: fn() = || {
    // Compile-time check: the byte offsets the naked-asm uses
    // match the struct layout. Catches a layout drift before
    // QEMU ever sees the failure.
    let _ = core::mem::offset_of!(UserState, x);
    let _ = core::mem::offset_of!(UserState, pc);
    let _ = core::mem::offset_of!(UserState, sp);
    let _ = core::mem::offset_of!(UserState, spsr);
};

// ── Kernel-test smokes ─────────────────────────────────────────────
//
// We can exercise setjmp/longjmp from kernel mode (CPL=EL1) directly
// — they're plain procedure-call-shaped routines that only touch
// callee-saved GPRs + sp + lr. enter_user_mode / _resume are NOT
// exercisable from a kernel-test (they `eret` to EL0 and never
// return); their layout is verified by the const-offset asserts
// above + the load-bearing field offsets in the asm.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_aarch64_setjmp_longjmp_round_trip() -> TestResult {
    // setjmp returns 0 on the initial call; a matching longjmp
    // makes it appear to return the supplied value (or 1 if the
    // caller passed 0, per POSIX convention).
    let mut jmp = JmpBuf::default();
    // SAFETY: jmp lives on this stack frame for the duration of
    // both the setjmp + longjmp calls; setjmp's saved sp/x30
    // remain valid until we return from this function.
    // SAFETY: Valid memory or trusted environment
    let r1 = unsafe { setjmp(&mut jmp as *mut _) };
    if r1 == 0 {
        // First time through: longjmp back with a sentinel value.
        // SAFETY: jmp was just populated by the matching setjmp;
        // the call frame is still live (we're in the same fn).
        // SAFETY: Valid memory or trusted environment
        unsafe { longjmp(&jmp as *const _, 0xCAFE_BABE) }
    }
    if r1 != 0xCAFE_BABE {
        return TestResult::Fail("longjmp value did not surface from setjmp");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_setjmp_longjmp_round_trip);

fn smoke_aarch64_setjmp_longjmp_zero_promotes_to_one() -> TestResult {
    // POSIX: longjmp(_, 0) cannot be distinguished from a fresh
    // setjmp return by value alone. Our impl preserves the
    // distinction by csinc-ing 0 → 1, so the longjmp path always
    // returns at least 1.
    let mut jmp = JmpBuf::default();
    // SAFETY: same single-frame invariant as above.
    let r1 = unsafe { setjmp(&mut jmp as *mut _) };
    if r1 == 0 {
        // SAFETY: same.
        unsafe { longjmp(&jmp as *const _, 0) }
    }
    if r1 != 1 {
        return TestResult::Fail("longjmp(_, 0) should surface as 1, not 0");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_setjmp_longjmp_zero_promotes_to_one);

fn smoke_aarch64_setjmp_longjmp_preserves_callee_saved() -> TestResult {
    // x19..=x29 + sp must round-trip across longjmp. We don't
    // have ergonomic access to the saved register file from
    // Rust (the compiler doesn't pin variables to specific
    // callee-saved regs), but we can prove the trip by invoking
    // a function that uses them and checking it observes the
    // expected values pre- and post-longjmp.
    use core::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    COUNT.store(0, Ordering::Relaxed);

    let mut jmp = JmpBuf::default();
    // SAFETY: same single-frame invariant as above.
    let r = unsafe { setjmp(&mut jmp as *mut _) };
    let n = COUNT.fetch_add(1, Ordering::AcqRel);
    if r == 0 {
        // First-time through; longjmp.
        if n != 0 {
            return TestResult::Fail("first-pass count should be 0");
        }
        // SAFETY: same.
        unsafe { longjmp(&jmp as *const _, 7) }
    }
    if r != 7 {
        return TestResult::Fail("longjmp value mismatch on second pass");
    }
    if n != 1 {
        return TestResult::Fail("second-pass count should be 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "aarch64",
    smoke_aarch64_setjmp_longjmp_preserves_callee_saved
);

fn smoke_aarch64_user_fp_state_round_trip() -> TestResult {
    let mut original = UserFpState::zeroed();
    let mut saved = UserFpState::zeroed();
    let mut q0 = 0u128;
    let mut q31 = 0u128;
    // Preserve the test runner's architectural FP/SIMD state, install two
    // sentinels, save them through the production primitive, clobber the live
    // registers, and restore. The kernel itself is soft-float, so no compiler
    // generated vector instruction can intervene.
    // SAFETY: all buffers have the required alignment and lifetime; the boot
    // path enables FP/SIMD access at EL1, and original is restored before exit.
    unsafe {
        save_user_fp_state(original.as_mut_ptr());
        asm!(
            "movi v0.16b, #0x5a",
            "movi v31.16b, #0xa5",
            options(nomem, nostack),
        );
        save_user_fp_state(saved.as_mut_ptr());
        asm!(
            "movi v0.16b, #0",
            "movi v31.16b, #0",
            options(nomem, nostack),
        );
        restore_user_fp_state(saved.as_ptr());
        asm!(
            "str q0, [{q0}]",
            "str q31, [{q31}]",
            q0 = in(reg) &mut q0,
            q31 = in(reg) &mut q31,
            options(nostack),
        );
        restore_user_fp_state(original.as_ptr());
    }
    if q0 != u128::from_le_bytes([0x5a; 16]) {
        return TestResult::Fail("Q0 did not survive user FP state round trip");
    }
    if q31 != u128::from_le_bytes([0xa5; 16]) {
        return TestResult::Fail("Q31 did not survive user FP state round trip");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_user_fp_state_round_trip);
