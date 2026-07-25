#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setpgid(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let pgid = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    // arg0/arg1 are *visible* pids (0 = self / pgid-of-self); the
    // PGID_TABLE is keyed by and stores task ids, so translate in.
    let target = if pid == 0 {
        current_task_id()
    } else {
        pgid_from_user(pid)
    };
    let value = if pgid == 0 {
        target
    } else {
        pgid_from_user(pgid)
    };
    let mut g = PGID_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    m.insert(target, value);
    ctx.set_return(SyscallReturn::ok(0));
}
