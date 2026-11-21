//! The i386 system-call table (`arch/x86/entry/syscalls/syscall_32.tbl`).
//!
//! [`super::dispatch`] reaches this after seccomp and the TLS calls; it
//! owns nothing but the number → handler mapping. An i386 call whose
//! arguments match a native handler's is served with [`forward`]; one that
//! needs converting (64-bit argument pairs, compat structs) gets its own
//! handler. Unlisted numbers answer -ENOSYS (`sys_ni_syscall`).

use crate::syscall::{Syscall, SyscallReturn, TrapContext};

/// Serve i386 system call `nr` on `ctx`. Returns the native syscall that
/// served it, if any: [`super::dispatch`] classifies restartability by it
/// when the call parks to be re-executed.
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let _ = nr;
    ctx.set_return(SyscallReturn::not_implemented());
    None
}

/// Serve an i386 call with the native handler for `variant`: the context's
/// six arguments are already ebx, ecx, edx, esi, edi, ebp zero-extended.
pub fn forward(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    crate::syscall::dispatch_native(variant, ctx);
    Some(variant)
}
