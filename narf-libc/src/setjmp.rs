//! `<setjmp.h>` — non-local goto.
//!
//! `setjmp(env)` saves the caller's callee-saved registers + stack
//! pointer + return address into `env` and returns 0. A subsequent
//! `longjmp(env, val)` restores those registers and re-returns from
//! the saved `setjmp` site, this time with the value `val` (or 1 if
//! `val == 0`, per C99 §7.13.2.1: "if val is 0, setjmp returns 1").
//!
//! Layout: `jmp_buf` is an opaque, fixed-size array of u64s. The
//! exact register order is private to this module; consumers only
//! see `jmp_buf` and call setjmp / longjmp.
//!
//! x86_64 SysV: callee-saved are rbx, rbp, r12, r13, r14, r15, plus
//! rsp + rip. 8 slots.
//!
//! aarch64 AAPCS: callee-saved are x19–x30 (12 regs), sp, plus
//! d8–d15 (8 FP regs). 21 slots; we round to 22 for alignment.
//!
//! No signal-mask saving (POSIX `sigsetjmp`/`siglongjmp` is a
//! follow-up; today's NARF signal model doesn't carry a per-task
//! mask the libc surface manipulates yet).

#![allow(non_camel_case_types)]

/// Number of u64 slots in `jmp_buf`. Sized for the wider arch
/// (aarch64) so the same array works on both targets — the x86_64
/// implementation only fills the first 8.
pub const JMP_BUF_LEN: usize = 24;

/// Opaque saved-context buffer. `#[repr(C)]` so the layout is
/// stable across the asm boundary.
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct jmp_buf {
    pub slots: [u64; JMP_BUF_LEN],
}

impl Default for jmp_buf {
    fn default() -> Self {
        Self {
            slots: [0; JMP_BUF_LEN],
        }
    }
}

impl core::fmt::Debug for jmp_buf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("jmp_buf").finish_non_exhaustive()
    }
}

// ── x86_64 ─────────────────────────────────────────────────────────
//
// Slot layout (filled by setjmp):
//   [0] = rbx
//   [1] = rbp
//   [2] = r12
//   [3] = r13
//   [4] = r14
//   [5] = r15
//   [6] = saved rsp (rsp at the point of the call, AFTER the
//         return address has been pushed — i.e. callee's frame
//         base before any prologue).
//   [7] = return address (the rip the longjmp should jump to)

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl setjmp",
    ".globl longjmp",
    // setjmp(rdi = *mut jmp_buf) -> i32
    //
    // The return address is at [rsp]; rsp post-call is rdi caller's
    // stack pointer + 8. We save callee-saved + the rsp we want
    // longjmp to restore + the return address. Then return 0.
    "setjmp:",
    "    mov [rdi + 0x00], rbx",
    "    mov [rdi + 0x08], rbp",
    "    mov [rdi + 0x10], r12",
    "    mov [rdi + 0x18], r13",
    "    mov [rdi + 0x20], r14",
    "    mov [rdi + 0x28], r15",
    // rsp at call entry is `rsp + 8` (peel off the return addr).
    "    lea rax, [rsp + 8]",
    "    mov [rdi + 0x30], rax",
    "    mov rax, [rsp]",
    "    mov [rdi + 0x38], rax",
    "    xor eax, eax",
    "    ret",
    // longjmp(rdi = *mut jmp_buf, esi = val) -> !
    //
    // Restore callee-saved, set rsp to the saved value, push the
    // saved return address, set rax = val (or 1 if val == 0), then
    // ret — which lands at the saved rip with rax as the apparent
    // setjmp return value.
    "longjmp:",
    "    mov rbx, [rdi + 0x00]",
    "    mov rbp, [rdi + 0x08]",
    "    mov r12, [rdi + 0x10]",
    "    mov r13, [rdi + 0x18]",
    "    mov r14, [rdi + 0x20]",
    "    mov r15, [rdi + 0x28]",
    "    mov rsp, [rdi + 0x30]",
    "    mov rax, [rdi + 0x38]",
    // rax now holds the saved return address; push it so `ret`
    // walks back to setjmp's call site.
    "    push rax",
    // val == 0 -> 1, else val. Test esi; cmove to 1 if zero.
    "    mov eax, esi",
    "    test eax, eax",
    "    mov ecx, 1",
    "    cmove eax, ecx",
    "    ret",
);

// ── aarch64 ────────────────────────────────────────────────────────
//
// Slot layout:
//   [0..=11] = x19..x30
//   [12]     = sp
//   [13..=20] = d8..d15
//   [21]     = lr (== x30; duplicated for symmetry)
//   [22..23] = padding to keep the struct 16-aligned

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl setjmp",
    ".globl longjmp",
    "setjmp:",
    "    stp x19, x20, [x0, #0x00]",
    "    stp x21, x22, [x0, #0x10]",
    "    stp x23, x24, [x0, #0x20]",
    "    stp x25, x26, [x0, #0x30]",
    "    stp x27, x28, [x0, #0x40]",
    "    stp x29, x30, [x0, #0x50]",
    "    mov x9, sp",
    "    str x9, [x0, #0x60]",
    "    stp d8,  d9,  [x0, #0x68]",
    "    stp d10, d11, [x0, #0x78]",
    "    stp d12, d13, [x0, #0x88]",
    "    stp d14, d15, [x0, #0x98]",
    "    mov w0, wzr",
    "    ret",
    "longjmp:",
    "    ldp x19, x20, [x0, #0x00]",
    "    ldp x21, x22, [x0, #0x10]",
    "    ldp x23, x24, [x0, #0x20]",
    "    ldp x25, x26, [x0, #0x30]",
    "    ldp x27, x28, [x0, #0x40]",
    "    ldp x29, x30, [x0, #0x50]",
    "    ldr x9,  [x0, #0x60]",
    "    mov sp, x9",
    "    ldp d8,  d9,  [x0, #0x68]",
    "    ldp d10, d11, [x0, #0x78]",
    "    ldp d12, d13, [x0, #0x88]",
    "    ldp d14, d15, [x0, #0x98]",
    // val == 0 -> 1, else val.
    "    mov w2, #1",
    "    cmp w1, #0",
    "    csel w0, w2, w1, eq",
    "    ret",
);

extern "C" {
    /// Save calling context to `env` and return 0. A later
    /// `longjmp(env, v)` returns control to this call site with `v`
    /// (or 1 if `v == 0`) as the apparent return value.
    pub fn setjmp(env: *mut jmp_buf) -> i32;
    /// Restore the context saved in `env` and re-return from the
    /// matching `setjmp` with value `val` (or 1 if `val == 0`).
    /// Never returns to the caller.
    pub fn longjmp(env: *mut jmp_buf, val: i32) -> !;
}

// ── sigsetjmp / siglongjmp ──────────────────────────────────────────
//
// POSIX `sigsetjmp(env, savemask)` is `setjmp(env)` plus optional
// signal-mask save/restore. NARF doesn't carry a per-task signal
// mask in user mode (the kernel surfaces a structural sigprocmask
// stub but the libc shim today is a no-op), so the `savemask`
// argument is accepted-and-ignored. The forwarding macro shape
// matches POSIX.1-2017: same `jmp_buf` type, same return contract.
//
// `siglongjmp(env, val)` is exactly `longjmp(env, val)` — there's
// no mask to restore.

/// Opaque sigjmp_buf: same shape as [`jmp_buf`] (POSIX.1-2017
/// permits growing it for the saved sigset_t; NARF doesn't ship a
/// sigset representation worth saving, so we alias).
pub type sigjmp_buf = jmp_buf;

/// `sigsetjmp(env, savemask)` — POSIX. `savemask` is recorded into
/// the supplied buffer for symmetry with `siglongjmp` but the
/// signal-mask itself is not captured (NARF has no live mask).
///
/// # Safety
/// `env` must be a writable `*mut sigjmp_buf` and outlive the
/// matching `siglongjmp`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigsetjmp(env: *mut sigjmp_buf, _savemask: i32) -> i32 {
    // SAFETY: forwarded; setjmp expects the same buffer shape.
    unsafe { setjmp(env) }
}

/// `siglongjmp(env, val)` — POSIX. The "restore signal mask if
/// `sigsetjmp` saved one" step is a no-op on NARF.
///
/// # Safety
/// See [`longjmp`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglongjmp(env: *mut sigjmp_buf, val: i32) -> ! {
    // SAFETY: forwarded.
    unsafe { longjmp(env, val) }
}
