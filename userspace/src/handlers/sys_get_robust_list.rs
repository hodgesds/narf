#[allow(unused_imports)]
use super::*;

/// `get_robust_list(pid, head_ptr, len_ptr)` — read back the robust
/// futex list head registered for `pid` (0 = the caller).
pub(crate) fn sys_get_robust_list(ctx: &mut dyn TrapContext) {
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
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        proc_pid_to_tid(outer)
    };
    let (head, len) = {
        let g = ROBUST_LIST_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).copied())
            .unwrap_or((0, 0))
    };
    if head_out != 0 {
        // SAFETY: `head_out` is the user `void**` out-pointer; copy_to_user
        // range-validates the 8-byte write.
        if unsafe { copy_to_user(head_out, &head.to_ne_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    if len_out != 0 {
        // SAFETY: `len_out` is the user `size_t*` out-pointer; copy_to_user
        // range-validates the 8-byte write.
        let _ = unsafe { copy_to_user(len_out, &len.to_ne_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}
