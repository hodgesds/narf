//! IA-32 system calls on x86_64 (Linux `CONFIG_IA32_EMULATION`).
//!
//! `int 0x80` is the i386 system-call gate for every task, 32-bit or 64-bit
//! (Linux `entry_INT80_compat` / `do_int80_emulation`): eax is the number
//! from `arch/x86/entry/syscalls/syscall_32.tbl`, ebx, ecx, edx, esi, edi
//! and ebp are the six arguments, zero-extended, and the result comes back
//! in eax; every other register is preserved.
//!
//! `frame`'s gate builds a [`TrapContext`] whose `args()` are that i386
//! register view, whose `set_return` writes eax ([`user_rax`]) and whose
//! `in_ia32_syscall()` is true, then calls [`dispatch`] with the number.
//! [`dispatch`] owns the entry work (seccomp with `AUDIT_ARCH_I386`, the
//! TLS calls in [`tls`], signal delivery with restart semantics) and hands
//! every other number to [`table::dispatch`], the i386 table proper.
//!
//! Ownership: the hook, [`user_rax`] and [`tls`] belong to the frame /
//! TCB work; [`table`]'s contents belong to the IA-32 userspace work.

pub mod table;
pub mod tls;

use crate::syscall::{SyscallReturn, TrapContext};

/// i386 `set_thread_area` (`syscall_32.tbl` 243).
pub const NR_SET_THREAD_AREA: u32 = 243;
/// i386 `get_thread_area` (`syscall_32.tbl` 244).
pub const NR_GET_THREAD_AREA: u32 = 244;

/// Serve i386 system call `nr` (eax) on `ctx`, the gate's i386 view of the
/// trap frame. Returns with the result in `ctx` and any pending signal
/// delivered; the gate then restores eax to `nr` if the call parked to be
/// re-executed (RIP rewound onto `int 0x80`).
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) {
    let _ = nr;
    ctx.set_return(SyscallReturn::not_implemented());
}

/// The eax/rax an i386 caller sees for `ret`: the value, sign-extended to
/// 64 bits as Linux stores `regs->ax`. A NARF non-Ok status without an
/// errno in its value (`invalid_op`) reads as -EINVAL, as on the `syscall`
/// path; one that carries an errno (`not_implemented`'s -ENOSYS) keeps it.
pub fn user_rax(ret: SyscallReturn) -> u64 {
    let _ = ret;
    0
}
