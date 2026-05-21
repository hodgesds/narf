//! x86_64 `setjmp` / `longjmp` for the S3 suspend/resume bridge.
//!
//! The wake trampoline runs in a context with no live Rust stack
//! frame — it lgdt/lidt/cr3-restores then jumps to a Rust
//! continuation. The continuation reaches back into the
//! suspending thread via `longjmp` so the caller of `suspend()`
//! observes a normal-looking return.
//!
//! SysV-AMD64 callee-saved registers (System V AMD64 ABI §3.2.1):
//! `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`. Plus we save `rsp`
//! (caller's stack pointer post-`call`) and the return-address
//! read from `[rsp]` at setjmp entry, so longjmp can restore the
//! exact PC + frame the original setjmp caller would have
//! returned to.

use core::arch::naked_asm;

/// x86_64 long-jump buffer — 8 u64 slots, layout load-bearing for
/// the naked asm below.
///
/// ```text
///   slots[0] = rbx      slots[1] = rbp
///   slots[2] = r12      slots[3] = r13
///   slots[4] = r14      slots[5] = r15
///   slots[6] = rsp (after pop of return addr)
///   slots[7] = rip (return addr the setjmp call would resume at)
/// ```
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct JmpBuf {
    pub slots: [u64; 8],
}

/// Snapshot caller's callee-saved registers + return-PC + stack
/// pointer into `*jmp` and return 0. A matching [`longjmp`] makes
/// this call appear to return `val` (or 1 if val is 0).
///
/// SysV-AMD64: `rdi` carries the `jmp` pointer; the return value
/// is in `rax`.
///
/// # Safety
/// `jmp` must be a writable, suitably-aligned `JmpBuf` for at
/// least the lifetime of any matching `longjmp`. The frame
/// containing `*jmp` must still be live (its stack range is
/// what the saved `rsp` points into).
#[unsafe(naked)]
pub unsafe extern "C" fn setjmp(jmp: *mut JmpBuf) -> u64 {
    naked_asm!(
        // rdi = jmp.
        // Save callee-saved GPRs into slots[0..6].
        "mov [rdi + 0],  rbx",
        "mov [rdi + 8],  rbp",
        "mov [rdi + 16], r12",
        "mov [rdi + 24], r13",
        "mov [rdi + 32], r14",
        "mov [rdi + 40], r15",
        // Caller's rsp = our rsp + 8 (skip the `call` push of return-PC).
        // Save it into slot 6.
        "lea rax, [rsp + 8]",
        "mov [rdi + 48], rax",
        // Return-PC = qword at [rsp]. Save into slot 7.
        "mov rax, [rsp]",
        "mov [rdi + 56], rax",
        // Return 0 to setjmp's caller.
        "xor eax, eax",
        "ret",
    );
}

/// Restore the register file from `*jmp` + "return" from the
/// matching [`setjmp`] with value `val`. Never returns to the
/// caller of `longjmp` itself.
///
/// SysV-AMD64: `rdi` = jmp pointer, `rsi` = val. The "return"
/// happens via direct `jmp` to the saved return-PC after
/// reloading rsp + rax-with-the-promoted-val.
///
/// # Safety
/// - `jmp` was populated by an earlier `setjmp` whose call frame
///   is still live (saved rsp + return-PC still describe a valid
///   kernel stack).
/// - In the S3 path, "still live" means: the suspending thread's
///   stack page must not have been recycled across the sleep.
///   Since suspend() runs on the boot CPU with interrupts off
///   right up to the PM1 write, and the resume trampoline jumps
///   straight back into longjmp before any scheduler tick, the
///   stack frame is preserved.
#[unsafe(naked)]
pub unsafe extern "C" fn longjmp(jmp: *const JmpBuf, val: u64) -> ! {
    naked_asm!(
        // rdi = jmp, rsi = val.
        "mov rbx, [rdi + 0]",
        "mov rbp, [rdi + 8]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        // Restore rsp BEFORE we pop the saved return-PC into rax.
        "mov rsp, [rdi + 48]",
        // Read the saved return-PC into rcx (we'll jmp to it).
        "mov rcx, [rdi + 56]",
        // Promote val=0 → 1 so setjmp's caller can always tell
        // "we came back via longjmp" from "first-time return".
        "test rsi, rsi",
        "mov rax, rsi",
        "jne 2f",
        "mov rax, 1",
        "2:",
        // Jump straight to the saved return-PC. Equivalent to
        // a return from setjmp — rsp is what it would have been
        // had setjmp returned normally; the saved return-PC is
        // what setjmp's `ret` would have jumped to.
        "jmp rcx",
    );
}

// Compile-time check: the byte offsets the asm uses match the
// struct layout. Drift on either side trips this before QEMU
// has a chance to.
const _: () = {
    assert!(core::mem::offset_of!(JmpBuf, slots) == 0);
    assert!(core::mem::size_of::<JmpBuf>() == 64);
    assert!(core::mem::align_of::<JmpBuf>() == 16);
};
