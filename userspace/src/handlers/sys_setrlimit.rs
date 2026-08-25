#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setrlimit(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let resource = args.arg0 as usize;
    let in_ptr = args.arg1;
    if in_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    // Read two u64s from user buffer under the SMAP bracket.
    let mut buf = [0u8; 16];
    // SAFETY: `in_ptr` is the user rlimit pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 16-byte read.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut buf, in_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let cur = u64::from_ne_bytes(buf[..8].try_into().unwrap());
    let max = u64::from_ne_bytes(buf[8..].try_into().unwrap());
    let task = current_task_id();
    match update_rlimit_atomic(task, resource, Some(RLimitPair { cur, max })) {
        Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        Err(errno) => ctx.set_return(SyscallReturn::ok((-errno) as u64)),
    }
}
