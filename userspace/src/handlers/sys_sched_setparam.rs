#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_setparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let inp = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if inp == 0 {
        ctx.set_return(fail);
        return;
    }
    // Read one i32 from user space under the SMAP bracket.
    let mut buf = [0u8; 4];
    // SAFETY: `inp` is the user sched_param pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 4-byte read.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut buf, inp) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let val = i32::from_ne_bytes(buf);
    let task = if pid == 0 { current_task_id() } else { pid };
    let mut g = SCHED_PARAM_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    m.insert(task, val);
    ctx.set_return(SyscallReturn::ok(0));
}
