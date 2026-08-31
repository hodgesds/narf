#[allow(unused_imports)]
use super::*;

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
/// What `copy_user_cstr_checked` returns for a name that reaches the cap
/// with no terminator. Linux reports that case as -ENOENT, not
/// -ENAMETOOLONG — see the mapping below.
const ENAMETOOLONG_FROM_COPY: i64 = 36;

#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

/// `delete_module(2)` — `kernel/module/main.c::SYSCALL_DEFINE2(delete_module)`.
///
/// ```text
/// SYSCALL_DEFINE2(delete_module, const char __user *, name_user,
///                 unsigned int, flags)
/// {
///         if (!capable(CAP_SYS_MODULE) || modules_disabled) return -EPERM;
///         len = strncpy_from_user(name, name_user, MODULE_NAME_LEN);
///         if (len == 0 || len == MODULE_NAME_LEN) return -ENOENT;
///         if (len < 0) return len;
/// ```
///
/// Two things this got wrong. The second argument is **flags**, not a length —
/// reading it as one meant a caller passing `O_NONBLOCK` (which is what
/// `rmmod` does) had its flag word interpreted as the size of the name. And
/// the name was read with a raw `from_raw_parts` over the user pointer, with
/// no range validation at all.
///
/// The name is NUL-terminated and capped at `MODULE_NAME_LEN`; a name that
/// is empty or fills the buffer is -ENOENT — "no such module", because
/// neither can name one — rather than an argument error.
pub(crate) fn sys_delete_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();

    // Ahead of reading the name: `capable()` outranks -EFAULT and -ENOENT
    // here, so an unprivileged caller cannot use this syscall to probe which
    // addresses are mapped.
    if !capable(CAP_SYS_MODULE) {
        ctx.set_return(fail(EPERM));
        return;
    }

    // `MODULE_NAME_LEN` is `64 - sizeof(unsigned long)` (`moduleparam.h:19`),
    // i.e. 56 on 64-bit. arg1 is `flags`; NARF never blocks on unload, so
    // O_NONBLOCK/O_TRUNC have nothing to change and it is read and ignored,
    // not mistaken for a length.
    const MODULE_NAME_LEN: usize = 64 - core::mem::size_of::<u64>();
    let name = match copy_user_cstr_checked(args.arg0, MODULE_NAME_LEN) {
        Ok(s) => s,
        // A name reaching the cap with no terminator is `len ==
        // MODULE_NAME_LEN` in Linux, which is -ENOENT, not the
        // -ENAMETOOLONG a path syscall would give.
        Err(ENAMETOOLONG_FROM_COPY) => {
            ctx.set_return(fail(ENOENT));
            return;
        }
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-e) as u64));
            return;
        }
    };
    if name.is_empty() {
        ctx.set_return(fail(ENOENT));
        return;
    }

    match narf_modules::syscalls::sys_delete_module(&name) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(SyscallReturn::ok((e.to_errno() as i64) as u64)),
    }
}
