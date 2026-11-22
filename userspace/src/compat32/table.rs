//! The i386 system-call table (`arch/x86/entry/syscalls/syscall_32.tbl`).
//!
//! [`super::dispatch`] reaches this after seccomp and the TLS calls; it
//! owns nothing but the number → handler mapping. An i386 call whose
//! arguments match a native handler's is served with [`forward`]; one that
//! needs converting (64-bit argument pairs, compat structs) gets its own
//! handler. Unlisted numbers answer -ENOSYS (`sys_ni_syscall`).
//!
//! The entries below are the phase-0 seed the gate's own tests need; the
//! IA-32 userspace work owns and extends the table.

use crate::syscall::{Syscall, SyscallReturn, TrapContext};

/// i386 `exit`.
pub const NR_EXIT: u32 = 1;
/// i386 `getpid`.
pub const NR_GETPID: u32 = 20;
/// i386 `uname` (`sys_newuname`; `struct new_utsname` is ABI-identical).
pub const NR_UNAME: u32 = 122;
/// i386 `sched_yield`.
pub const NR_SCHED_YIELD: u32 = 158;
/// i386 `gettid`.
pub const NR_GETTID: u32 = 224;
/// i386 `exit_group`.
pub const NR_EXIT_GROUP: u32 = 252;

/// Serve i386 system call `nr` on `ctx`. Returns the native syscall that
/// served it, if any: [`super::dispatch`] classifies restartability by it
/// when the call parks to be re-executed.
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) -> Option<Syscall> {
    match nr {
        NR_EXIT => forward(ctx, Syscall::ExitTask),
        NR_GETPID => forward(ctx, Syscall::GetPid),
        NR_UNAME => forward(ctx, Syscall::Uname),
        NR_SCHED_YIELD => forward(ctx, Syscall::Yield),
        NR_GETTID => forward(ctx, Syscall::Gettid),
        NR_EXIT_GROUP => forward(ctx, Syscall::ExitGroup),
        _ => {
            ctx.set_return(SyscallReturn::not_implemented());
            None
        }
    }
}

/// Serve an i386 call with the native handler for `variant`: the context's
/// six arguments are already ebx, ecx, edx, esi, edi, ebp zero-extended.
pub fn forward(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    crate::syscall::dispatch_native(variant, ctx);
    Some(variant)
}
