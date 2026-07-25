#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_getparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let out = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = if pid == 0 { current_task_id() } else { pid };
    let g = SCHED_PARAM_TABLE.lock();
    let val = g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0);
    // Write one i32 to user space under the SMAP bracket.
    // SAFETY: `out` is the user sched_param pointer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out, &val.to_ne_bytes()) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
