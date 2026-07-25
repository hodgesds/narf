#[allow(unused_imports)]
use super::*;

/// `ioprio_get(which, who)` — get I/O priority.
/// arg0 = which, arg1 = who (pid).
/// Returns stored priority or Linux default (IOPRIO_CLASS_BE=2 << 13) | 4.
pub(crate) fn sys_ioprio_get(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i32;
    let who = args.arg1;
    let g = IOPRIO_TABLE.lock();
    let result = g
        .as_ref()
        .and_then(|m| m.get(&(which, who)).copied())
        .unwrap_or((2u32 << 13) | 4); // IOPRIO_CLASS_BE=2 (bits 13-15), prio=4
    ctx.set_return(SyscallReturn::ok(result as u64));
}
