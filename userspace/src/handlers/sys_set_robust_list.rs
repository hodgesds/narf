#[allow(unused_imports)]
use super::*;

/// `sizeof(struct robust_list_head)` on a 64-bit ABI: `struct robust_list
/// *list` + `long futex_offset` + `struct robust_list *list_op_pending`
/// (`include/uapi/linux/futex.h`).
pub(crate) const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE2(set_robust_list)` —
/// register the calling thread's robust futex list head.
///
/// ```text
/// /* The kernel knows only one size for now: */
/// if (unlikely(len != sizeof(*head)))
///         return -EINVAL;
/// ```
///
/// The length is the ABI version handshake for this call: it is how a libc
/// built against a future, larger `robust_list_head` finds out that this
/// kernel would walk its list with the OLD layout. Accepting any length
/// means the kernel later reads `futex_offset` from the wrong offset and
/// marks the wrong words FUTEX_OWNER_DIED — silent corruption instead of
/// an EINVAL the libc can fall back from. (glibc and musl both pass
/// exactly 24 here, so this rejects only genuinely mismatched callers.)
/// `sizeof(struct compat_robust_list_head)`: three 32-bit words. The i386
/// `set_robust_list` (311, `compat_sys_set_robust_list`) accepts only this,
/// and the length recorded with the head is how the exit-time walk knows to
/// read the list with 32-bit pointers (`compat_exit_robust_list`).
pub(crate) const COMPAT_ROBUST_LIST_HEAD_SIZE: u64 = 12;

pub(crate) fn sys_set_robust_list(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let head_size = if ctx.in_ia32_syscall() {
        COMPAT_ROBUST_LIST_HEAD_SIZE
    } else {
        ROBUST_LIST_HEAD_SIZE
    };
    if a.arg1 != head_size {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let task = current_task_id();
    let mut g = ROBUST_LIST_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    m.insert(task, (a.arg0, a.arg1));
    ctx.set_return(SyscallReturn::ok(0));
}
