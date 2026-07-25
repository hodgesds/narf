#[allow(unused_imports)]
use super::*;

/// `sched_setattr(pid, attr, flags)`.
pub(crate) fn sys_sched_setattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let attr_ptr = a.arg1;
    if a.arg2 != 0 || attr_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // The first u32 is the caller-declared struct size.
    let size = read_user_u32(attr_ptr) as usize;
    if size < SCHED_ATTR_SIZE {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL / E2BIG
        return;
    }
    let to_read = size.min(SCHED_ATTR_SIZE);
    // SAFETY: attr_ptr is non-zero; copy_from_user_vec range-validates the read.
    let bytes = match unsafe { copy_from_user_vec(attr_ptr, to_read) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let mut buf = [0u8; SCHED_ATTR_SIZE];
    buf[..to_read].copy_from_slice(&bytes);
    let pid = a.arg0;
    let task = if pid == 0 { current_task_id() } else { pid };
    SCHED_ATTR_TABLE
        .lock()
        .get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(task, buf);
    ctx.set_return(SyscallReturn::ok(0));
}
