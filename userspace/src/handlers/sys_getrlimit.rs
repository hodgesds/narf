#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getrlimit(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let resource = args.arg0 as usize;
    let out_ptr = args.arg1;
    let task = current_task_id();
    let pair = match read_rlimit(task, resource) {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };
    // Linux validates `resource` in do_prlimit before attempting the user
    // copy, so getrlimit(invalid, NULL) is EINVAL rather than EFAULT.
    if out_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    // Write two u64s to user buffer under the SMAP bracket.
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&pair.cur.to_ne_bytes());
    buf[8..].copy_from_slice(&pair.max.to_ne_bytes());
    // SAFETY: `out_ptr` is the user rlimit buffer; copy_to_user range-validates
    // it and SMAP-brackets the write of the 16-byte `buf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
