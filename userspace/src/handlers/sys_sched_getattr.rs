#[allow(unused_imports)]
use super::*;

/// `sched_getattr(pid, attr, size, flags)`.
pub(crate) fn sys_sched_getattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let attr_ptr = a.arg1;
    let size = a.arg2 as usize;
    if a.arg3 != 0 || attr_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if size < SCHED_ATTR_SIZE {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL (buffer too small)
        return;
    }
    let pid = a.arg0;
    let task = if pid == 0 { current_task_id() } else { pid };
    let mut buf = SCHED_ATTR_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or([0u8; SCHED_ATTR_SIZE]);
    // The kernel always reports the actual struct size in the first word.
    buf[0..4].copy_from_slice(&(SCHED_ATTR_SIZE as u32).to_le_bytes());
    // SAFETY: attr_ptr is non-zero and size >= SCHED_ATTR_SIZE; copy_to_user
    // validates and SMAP-brackets the write.
    if unsafe { copy_to_user(attr_ptr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
