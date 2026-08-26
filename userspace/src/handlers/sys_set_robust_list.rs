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
pub(crate) fn sys_set_robust_list(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    let a = *ctx.args();
    if a.arg1 != ROBUST_LIST_HEAD_SIZE {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let task = current_task_id();
    let mut g = ROBUST_LIST_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    m.insert(task, (a.arg0, a.arg1));
    ctx.set_return(SyscallReturn::ok(0));
}
