#[allow(unused_imports)]
use super::*;

/// `ioprio_set(which, who, ioprio)` — set I/O priority.
/// arg0 = which, arg1 = who (pid), arg2 = ioprio.
/// Returns 0 on success.
pub(crate) fn sys_ioprio_set(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i32;
    let who = args.arg1;
    let ioprio = args.arg2 as u32;
    let mut g = IOPRIO_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert((which, who), ioprio);
    ctx.set_return(SyscallReturn::ok(0));
}
