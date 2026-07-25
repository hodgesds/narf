#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_umask(ctx: &mut dyn TrapContext) {
    let new_mask = (ctx.args().arg0 as u32) & 0o777;
    let task = current_task_id();
    let mut g = UMASK_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            // Treat lack of init as default-mask — return that
            // and accept the new mask going forward.
            ctx.set_return(SyscallReturn::ok(UMASK_DEFAULT as u64));
            return;
        }
    };
    let prior = m.insert(task, new_mask).unwrap_or(UMASK_DEFAULT);
    ctx.set_return(SyscallReturn::ok(prior as u64));
}
