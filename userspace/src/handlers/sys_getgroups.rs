#[allow(unused_imports)]
use super::*;

/// `getgroups(size, list)` — return the caller's supplementary group list.
pub(crate) fn sys_getgroups(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let size = args.arg0 as usize;
    let list = args.arg1;
    let groups = read_groups(current_task_id());
    if size == 0 {
        ctx.set_return(SyscallReturn::ok(groups.len() as u64));
        return;
    }
    if size < groups.len() {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    if list == 0 {
        ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
        return;
    }
    let mut bytes = alloc::vec::Vec::with_capacity(groups.len() * 4);
    for gid in groups {
        bytes.extend_from_slice(&gid.to_ne_bytes());
    }
    // SAFETY: list is a user pointer; copy_to_user validates and SMAP-brackets.
    if unsafe { copy_to_user(list, &bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
    } else {
        ctx.set_return(SyscallReturn::ok((bytes.len() / 4) as u64));
    }
}
