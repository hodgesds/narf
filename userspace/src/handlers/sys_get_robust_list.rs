#[allow(unused_imports)]
use super::*;

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE3(get_robust_list)` — read back
/// the robust futex list head registered for `pid` (0 = the caller).
///
/// ```text
/// struct robust_list_head __user *head = futex_get_robust_list_common(pid, false);
/// if (IS_ERR(head))
///         return PTR_ERR(head);
/// if (put_user(sizeof(*head), len_ptr))
///         return -EFAULT;
/// return put_user(head, head_ptr);
/// ```
///
/// Two things that are easy to get backwards and both matter to a caller:
///
///   * The LENGTH is written first, and its failure is fatal. NARF wrote
///     the head first and then ignored a failing length write entirely, so
///     `get_robust_list(0, &head, (void *)1)` reported success with `head`
///     already stored and `len` never written — the caller then walks the
///     list with an uninitialised stride.
///   * Linux always reports `sizeof(*head)`, never the length the task
///     registered. The value is the kernel's own ABI version, which is why
///     `set_robust_list` refuses any other length in the first place.
pub(crate) fn sys_get_robust_list(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EFAULT: i64 = 14;
    let a = *ctx.args();
    let head_out = a.arg1;
    let len_out = a.arg2;
    // Linux (kernel/futex/syscalls.c:59) resolves `pid` via find_task_by_vpid
    // — in the CALLER's pid namespace. Translate inner -> outer -> TaskId
    // before keying the robust-list table; the raw inner pid read an unrelated
    // task's list head. Audit finding #22.
    let task = if a.arg0 == 0 {
        current_task_id()
    } else {
        let Some(outer) = accept_pid_from(current_task_id(), a.arg0) else {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        };
        proc_pid_to_tid(outer)
    };
    let head = {
        let g = ROBUST_LIST_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).copied())
            .map(|(head, _len)| head)
            .unwrap_or(0)
    };
    // SAFETY: `len_out` is the user `size_t*` out-pointer; copy_to_user
    // range-validates the 8-byte write (a null pointer is rejected there,
    // which is exactly Linux's put_user failure).
    if unsafe {
        copy_to_user(
            len_out,
            &handler_sys_set_robust_list::ROBUST_LIST_HEAD_SIZE.to_ne_bytes(),
        )
    }
    .is_err()
    {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    // SAFETY: `head_out` is the user `void**` out-pointer; copy_to_user
    // range-validates the 8-byte write.
    if unsafe { copy_to_user(head_out, &head.to_ne_bytes()) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
